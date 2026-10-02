import json
import unittest
from unittest.mock import patch

from shapely.geometry import box
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from src.models.schema import Base, MonitoredLocation
from src.services import calculate_site_intersections, get_infrastructure_analytics, update_locations


class RegionalAnalyticsTests(unittest.TestCase):
    def test_intersections_accept_record_lists_and_preserve_site_fields(self):
        map_rows = [
            {"Name": "Inside", "Lat": 5, "Lon": 5, "Type": "NOC", "District": "North", "Priority": "P1"},
            {"Name": "Outside", "Lat": 15, "Lon": 15, "Type": "Field", "District": "South", "Priority": "P2"},
        ]
        polygons = [{
            "shape": box(0, 0, 10, 10),
            "event": "SPC: HIGH",
            "severity": "Watch",
            "is_toggled": True,
        }]

        toggled, master = calculate_site_intersections(map_rows, polygons)

        self.assertEqual(len(master), 1)
        self.assertEqual(master[0]["Monitored Site"], "Inside")
        self.assertEqual(master[0]["Type"], "NOC")
        self.assertEqual(toggled[0]["Intersecting Hazards"], "SPC: HIGH")

    def test_analytics_returns_json_ready_distributions_and_matrices(self):
        map_rows = [
            {"Name": "North", "Lat": 1, "Lon": 1},
            {"Name": "South", "Lat": 2, "Lon": 2},
        ]
        affected = [
            {"Monitored Site": "North", "Type": "NOC", "District": "North", "Priority": "P1", "Hazard": "SPC: HIGH"},
            {"Monitored Site": "North", "Type": "NOC", "District": "North", "Priority": "P1", "Hazard": "NWS Warning"},
            {"Monitored Site": "South", "Type": "Field", "District": "South", "Priority": "P2", "Hazard": "SPC: MDT"},
        ]

        analytics = get_infrastructure_analytics(map_rows, affected)

        self.assertEqual(analytics["total_sites"], 2)
        self.assertEqual(analytics["at_risk_sites"], 2)
        self.assertEqual(analytics["highest_risk"], "HIGH")
        self.assertEqual(analytics["type_distribution"][0], {"Facility Type": "NOC", "Count": 1})
        p1_row = next(row for row in analytics["priority_risk_matrix"] if row["Priority"] == "P1")
        self.assertEqual(p1_row["HIGH"], 1)
        self.assertEqual(analytics["spc_distribution"][0], {"SPC Risk": "HIGH", "count": 1})
        self.assertEqual(analytics["nws_distribution"][0], {"NWS Alert": "WARNING", "count": 1})
        json.dumps(analytics)

    def test_location_updates_accept_records_and_apply_all_fields(self):
        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        try:
            Base.metadata.create_all(engine)
            session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
            with session_factory() as session:
                location = MonitoredLocation(
                    name="Old Site", lat=34.0, lon=-92.0, loc_type="NOC",
                    district="North", priority="P3-Moderate",
                )
                session.add(location)
                session.commit()
                location_id = location.id

            with patch("src.services.SessionLocal", session_factory):
                update_locations([{
                    "ID": location_id,
                    "Name": "Updated Site",
                    "Type": "Field Office",
                    "District": "South",
                    "Priority": "P2-High",
                    "Lat": 36.0,
                    "Lon": -91.0,
                }])

            with session_factory() as session:
                updated = session.query(MonitoredLocation).filter_by(id=location_id).one()
                self.assertEqual(updated.name, "Updated Site")
                self.assertEqual(updated.loc_type, "Field Office")
                self.assertEqual(updated.district, "South")
                self.assertEqual(updated.priority, "P2-High")
                self.assertEqual(updated.lat, 36.0)
                self.assertEqual(updated.lon, -91.0)
        finally:
            engine.dispose()


if __name__ == "__main__":
    unittest.main()
