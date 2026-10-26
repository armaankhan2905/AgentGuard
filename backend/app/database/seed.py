"""Seed only fictional search records; repeated startup does not duplicate them."""

from sqlalchemy.dialects.sqlite import insert
from sqlalchemy.orm import Session

from app.models.demo_record import DemoRecord

DEMO_RECORDS = (
    {"code": "PRJ-001", "category": "project", "title": "Aurora demonstration project",
     "summary": "Fictional project: public report completed; documentation review pending."},
    {"code": "PRJ-002", "category": "project", "title": "Cobalt demo migration",
     "summary": "Fictional project: synthetic inventory migration is 60 percent complete."},
    {"code": "CUS-001", "category": "customer", "title": "Nimbus Example Studio",
     "summary": "Fictional customer requesting an Aurora demo; contact: team@nimbus.example."},
    {"code": "INV-001", "category": "inventory", "title": "Demo sensor kits",
     "summary": "Fictional inventory: 24 training kits in the sample warehouse."},
)


def seed_demo_records(db: Session) -> None:
    for record in DEMO_RECORDS:
        db.execute(insert(DemoRecord).values(**record).on_conflict_do_nothing(index_elements=["code"]))
    db.commit()
