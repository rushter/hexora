"""Train a CatBoost model on extracted package features.

First, generate the dataset from raw package metadata:

    hexora generate-features --input-path sample.jsonl --output-path dataset.jsonl

Run using uv:

    uv run train.py --input-path dataset.jsonl

Run using pip and python:

    pip install catboost polars scikit-learn numpy
    python train.py --input-path dataset.jsonl

The script first performs 5-fold cross-validation and reports precision scores,
then trains the final model on the full dataset and saves it to
crates/hexora_ml/src/model.json.

"""

# /// script
# dependencies = [
#   "catboost",
#   "polars",
#   "scikit-learn",
#   "numpy",
# ]
# ///

import argparse
import gzip
import logging
import os
import shutil

import catboost
import polars as pl
from sklearn.model_selection import cross_val_score

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def main():
    parser = argparse.ArgumentParser(
        description="Train a CatBoost model on package features."
    )
    parser.add_argument(
        "--input-path",
        required=True,
        help="Path to the ndjson features file",
    )
    args = parser.parse_args()

    logging.info("Loading data from %s", args.input_path)
    df = pl.read_ndjson(args.input_path)
    y = df["_label"].replace({"benign": 0, "malicious": 1}).cast(pl.Int64)
    df = df.fill_null(0).drop(["_label", "_file_path"])

    model = catboost.CatBoostClassifier(
        iterations=350,
        depth=5,
        learning_rate=0.03,
        verbose=0,
        random_seed=1337,
        l2_leaf_reg=15,
        min_data_in_leaf=3,
        class_weights=(5, 1),
        eval_metric="PRAUC",
        random_strength=2,
    )

    logging.info("Running 5-fold cross-validation")
    scores = cross_val_score(model, df, y, cv=5, scoring="precision")
    print(f"Scores: {scores}")
    print(f"Mean precision: {scores.mean():.6f}  Std: {scores.std():.6f}")

    logging.info("Training final model on full dataset")
    model.fit(df, y)
    path = "crates/hexora_ml/src/model.json"
    model.save_model(path, format="json")
    with open(path, "rb") as f_in:
        with gzip.open(f"{path}.gz", "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
    os.remove(path)
    logging.info("Model saved to %s.gz", path)


if __name__ == "__main__":
    main()
