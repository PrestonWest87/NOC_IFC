import unittest
import tempfile
from pathlib import Path
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
        with tempfile.TemporaryDirectory(prefix="noc-train-model-test-") as directory:
            model_path = Path(directory) / "model.pkl"

            def write_model(_model, path):
                Path(path).write_bytes(b"test-model")

            with patch.object(train_model, "MODEL_PATH", str(model_path)), patch.object(
                train_model, "SessionLocal", return_value=TrainingSession(rows)
            ), patch.object(train_model, "make_pipeline", return_value=model), patch.object(
                train_model.joblib, "dump", side_effect=write_model
            ) as dump:
                train_model.train()

            features, labels = model.fit.call_args.args
            self.assertEqual(features[0], "title 0 summary 0")
            self.assertEqual(labels, [1, 0] * 5)
            dump.assert_called_once()
            self.assertEqual(dump.call_args.args[0], model)
            temporary_path = Path(dump.call_args.args[1])
            self.assertNotEqual(temporary_path, model_path)
            self.assertEqual(model_path.read_bytes(), b"test-model")
            self.assertFalse(temporary_path.exists())


if __name__ == "__main__":
    unittest.main()
