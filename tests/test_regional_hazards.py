import unittest
from unittest.mock import MagicMock, patch


class RegionalHazardTests(unittest.TestCase):
    def test_regional_scheduler_tracks_both_usgs_fetches(self):
        from src.workers import infra_worker

        executor = MagicMock()
        submitted = [MagicMock() for _ in range(5)]
        executor.submit.side_effect = submitted
        session = MagicMock()
        cache = MagicMock(data={"type": "FeatureCollection", "features": []})
        session.query.return_value.filter_by.return_value.first.return_value = cache

        with patch.object(infra_worker.concurrent.futures, "ThreadPoolExecutor") as pool, patch.object(
            infra_worker.concurrent.futures, "as_completed", return_value=[]
        ) as completed, patch.object(infra_worker, "SessionLocal", return_value=session), patch.object(
            infra_worker, "check_earthquake_proximity"
        ), patch.object(infra_worker, "check_wildfire_proximity"):
            pool.return_value.__enter__.return_value = executor
            pool.return_value.__exit__.return_value = False
            infra_worker.fetch_regional_hazards()

        self.assertEqual(executor.submit.call_count, 5)
        self.assertEqual(completed.call_args.args[0], submitted)
        earthquake_jobs = [call.args for call in executor.submit.call_args_list if call.args[0] is infra_worker.fetch_usgs_earthquakes]
        self.assertEqual({args[1:] for args in earthquake_jobs}, {("ar", "usgs_ar"), ("oos", "usgs_oos")})


if __name__ == "__main__":
    unittest.main()
