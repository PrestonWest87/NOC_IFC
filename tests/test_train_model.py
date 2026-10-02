import unittest
from unittest.mock import Mock, patch

from src import train_model


class TrainingQuery:
    def __init__(self, rows):
        self.rows = rows

    def filter(self, *_args):
        return self

    def all(self):
        return self.rows


class TrainingSession:
    def __init__(self, rows):
        self.rows = rows

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def query(self, *_columns):
        return TrainingQuery(self.rows)


class TrainModelTests(unittest.TestCase):
    def test_training_uses_python_records_and_preserves_label_mapping(self):
        rows = [
            ("summary %d" % index, "Title %d" % index, 1 if index % 2 else 2)
            for index in range(10)
        ]
        model = Mock()
        with patch.object(train_model, "SessionLocal", return_value=TrainingSession(rows)), patch.object(
            train_model, "make_pipeline", return_value=model
        ), patch.object(train_model.joblib, "dump") as dump:
            train_model.train()

        features, labels = model.fit.call_args.args
        self.assertEqual(features[0], "title 0 summary 0")
        self.assertEqual(labels, [1, 0] * 5)
        dump.assert_called_once_with(model, train_model.MODEL_PATH)


if __name__ == "__main__":
    unittest.main()
