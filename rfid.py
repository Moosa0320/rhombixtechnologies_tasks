from dataclasses import dataclass, field
from typing import Dict, List, Optional
import time
import uuid
import random

@dataclass
class RFIDTag:
    tag_id: str
    owner_name: str
    card_number: str
    expiry: str
    can_be_scanned: bool = True

    def payload(self) -> Dict[str, str]:
        return {
            "tag_id": self.tag_id,
            "owner_name": self.owner_name,
            "card_number": self.card_number,
            "expiry": self.expiry,
        }

@dataclass
class Scanner:
    scanner_id: str
    name: str
    authorized: bool
    read_range_m: float

    def scan(self, tag: RFIDTag, distance_m: float) -> Optional[Dict[str,str]]:
        if distance_m > self.read_range_m:
            return None

        if not tag.can_be_scanned:
            return None

        payload = tag.payload()
        return payload

@dataclass
class RFIDBlocker:
    whitelist_scanner_ids: List[str] = field(default_factory=list)
    logs: List[Dict] = field(default_factory=list)
    redact_card_number: bool = True
    alert_on_unauthorized: bool = True

    def inspect_and_maybe_block(self, scanner: Scanner, tag_payload: Dict[str,str]) -> Optional[Dict[str,str]]:
        event = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "scanner_id": scanner.scanner_id,
            "scanner_name": scanner.name,
            "authorized_flag": scanner.authorized,
            "was_whitelisted": scanner.scanner_id in self.whitelist_scanner_ids,
            "tag_id": tag_payload.get("tag_id"),
        }

        if scanner.scanner_id in self.whitelist_scanner_ids:
            event["action"] = "allowed (whitelist)"
            delivered = tag_payload
        elif scanner.authorized:
            event["action"] = "allowed (authorized)"
            delivered = tag_payload
        else:
            if self.redact_card_number:
                redacted = tag_payload.copy()
                card = redacted.get("card_number", "")
                if card:
                    redacted["card_number"] = "XXXX-XXXX-XXXX-" + card[-4:]
                redacted["owner_name"] = "[REDACTED]"
                event["action"] = "redacted (blocked partial)"
                delivered = redacted
            else:
                event["action"] = "blocked (no data)"
                delivered = None

            if self.alert_on_unauthorized:
                event["alert"] = f"Unauthorized scan attempt by {scanner.name}"

        self.logs.append(event)
        return delivered

    def show_logs(self):
        for e in self.logs:
            print(f"{e['time']} | Scanner:{e['scanner_name']} ({e['scanner_id']}) | Action:{e['action']} | Tag:{e['tag_id']}")
            if e.get("alert"):
                print("  ALERT:", e["alert"])

def demo():
    tag1 = RFIDTag(tag_id=str(uuid.uuid4()), owner_name="Alice", card_number="4111222233334444", expiry="12/27")
    tag2 = RFIDTag(tag_id=str(uuid.uuid4()), owner_name="Bob", card_number="5500001111222233", expiry="03/26")

    pos = Scanner(scanner_id="POS-001", name="CoffeeShopPOS", authorized=True, read_range_m=0.5)
    shady = Scanner(scanner_id="SHADY-999", name="MallFreeReader", authorized=False, read_range_m=2.5)

    blocker = RFIDBlocker(whitelist_scanner_ids=["POS-001"], redact_card_number=True, alert_on_unauthorized=True)

    attempts = [
        (pos, tag1, 0.4),
        (shady, tag1, 1.0),
        (shady, tag2, 0.3),
        (pos, tag2, 0.6),
    ]

    for scanner, tag, dist in attempts:
        print(f"\nScanner '{scanner.name}' trying to read tag of {tag.owner_name} at distance {dist}m")
        raw = scanner.scan(tag, dist)
        if raw is None:
            print("  -> No response (out of range or tag silent)")
            continue
        delivered = blocker.inspect_and_maybe_block(scanner, raw)
        if delivered is None:
            print("  -> BLOCKED: scanner received nothing")
        else:
            print("  -> DELIVERED to scanner:", delivered)

    print("\n--- BLOCKER LOGS ---")
    blocker.show_logs()

if __name__ == "__main__":
    demo()
