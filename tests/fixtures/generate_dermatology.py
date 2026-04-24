"""Generate a dermatology-style CSV fixture mirroring the real data dictionary.

50 records. Includes ID fields (patient_id, case_id) and content fields
(diagnoses, dates, notes, counts, booleans). Deterministic via a fixed seed
so conformance tests can use it.
"""

import csv
import random
import uuid
from pathlib import Path

FIELDS = [
    "patient_id",
    "case_id",
    "primary_diagnosis",
    "secondary_diagnoses",
    "icd10_codes",
    "case_initiated_after_2020",
    "date_of_first_visit",
    "date_of_last_visit",
    "case_duration_days",
    "total_visits",
    "total_emrs",
    "emr_diagnosis_treatment_included",
    "emr_treatment_outcome_included",
    "emr_format",
    "patient_history_included",
    "current_medications_documented",
    "provider_notes_diagnosis",
    "provider_notes_ordered_tests",
    "provider_notes_test_outcomes",
    "provider_notes_outcomes_followups",
    "total_test_records",
    "test_types",
    "total_images",
    "image_modalities",
    "images_linked_to_emr",
    "patient_outcome_documented",
    "patient_outcome_summary",
    "country",
    "dermatologist_in_case_history",
]

DIAGNOSES = [
    ("Psoriasis", "L40.0"),
    ("Atopic dermatitis", "L20.81"),
    ("Acne vulgaris", "L70.0"),
    ("Seborrheic dermatitis", "L21.9"),
    ("Rosacea", "L71.9"),
    ("Basal cell carcinoma", "C44.91"),
    ("Melanoma in situ", "D03.9"),
    ("Contact dermatitis", "L25.9"),
    ("Urticaria", "L50.9"),
    ("Vitiligo", "L80"),
]

OUTCOMES = ["resolved", "ongoing treatment", "referred out", "lost to follow-up"]
COUNTRIES = ["US", "Japan"]
TEST_TYPES_POOL = ["biopsy", "patch test", "blood panel", "KOH prep", "dermoscopy"]
MODALITIES_POOL = ["Photographic", "Dermoscopy", "Confocal microscopy"]


def random_date(rng, start_year=2018, end_year=2024):
    year = rng.randint(start_year, end_year)
    month = rng.randint(1, 12)
    day = rng.randint(1, 28)
    return f"{month:02d}/{day:02d}/{year}"


def generate_row(rng):
    dx_primary, icd_primary = rng.choice(DIAGNOSES)
    n_secondary = rng.choice([0, 0, 1, 2])
    secondary = rng.sample([d for d in DIAGNOSES if d[0] != dx_primary], n_secondary)
    sec_names = "; ".join(d[0] for d in secondary)
    all_icds = "; ".join([icd_primary] + [d[1] for d in secondary])

    visits = rng.randint(2, 8)
    duration = rng.randint(14, 365)
    emrs = rng.randint(visits, visits * 2)

    test_types = rng.sample(TEST_TYPES_POOL, rng.randint(1, 3))
    modalities = rng.sample(MODALITIES_POOL, rng.randint(1, 2))

    return {
        "patient_id": str(uuid.UUID(int=rng.getrandbits(128))),
        "case_id": str(uuid.UUID(int=rng.getrandbits(128))),
        "primary_diagnosis": dx_primary,
        "secondary_diagnoses": sec_names if sec_names else "",
        "icd10_codes": all_icds,
        "case_initiated_after_2020": rng.choice(["Yes", "No"]),
        "date_of_first_visit": random_date(rng),
        "date_of_last_visit": random_date(rng),
        "case_duration_days": duration,
        "total_visits": visits,
        "total_emrs": emrs,
        "emr_diagnosis_treatment_included": "Yes",
        "emr_treatment_outcome_included": "Yes",
        "emr_format": rng.choice(["JSON", "Structured Text"]),
        "patient_history_included": "Yes",
        "current_medications_documented": "Yes",
        "provider_notes_diagnosis": "Yes",
        "provider_notes_ordered_tests": "Yes",
        "provider_notes_test_outcomes": "Yes",
        "provider_notes_outcomes_followups": "Yes",
        "total_test_records": rng.randint(1, 5),
        "test_types": "; ".join(test_types),
        "total_images": rng.randint(1, 12),
        "image_modalities": "; ".join(modalities),
        "images_linked_to_emr": "Yes",
        "patient_outcome_documented": "Yes",
        "patient_outcome_summary": rng.choice(OUTCOMES),
        "country": rng.choice(COUNTRIES),
        "dermatologist_in_case_history": "Yes",
    }


def generate(path: Path, n: int = 50, seed: int = 42):
    rng = random.Random(seed)
    rows = [generate_row(rng) for _ in range(n)]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return rows


if __name__ == "__main__":
    import sys
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("dermatology.csv")
    generate(out)
    print(f"Wrote {out}")
