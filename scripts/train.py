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
import logging

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
        iterations=200,
        depth=6,
        learning_rate=0.01,
        verbose=0,
        random_seed=1337,
    )

    logging.info("Running 5-fold cross-validation")
    scores = cross_val_score(model, df, y, cv=5, scoring="precision")
    print(f"Scores: {scores}")
    print(f"Mean accuracy: {scores.mean():.6f}  Std: {scores.std():.6f}")

    logging.info("Training final model on full dataset")
    model.fit(df, y)
    model.save_model("crates/hexora_ml/src/model.json", format="json")
    logging.info("Model saved to crates/hexora_ml/src/model.json")


if __name__ == "__main__":
    main()
