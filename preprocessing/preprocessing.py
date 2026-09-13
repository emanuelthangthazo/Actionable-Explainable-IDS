"""Data preprocessing module for CIC-IDS2017 dataset.

Per section 2 of WORKFLOW.md:
- Load CIC-IDS2017 CSVs from data/ directory
- Strip column names and string label values of trailing whitespace
- Remove NaN/null rows
- Remove Inf/-Inf values (e.g. in Flow Bytes/s, Flow Packets/s)
- Remove duplicate rows
- Encode target attack labels (Label column -> integer encodings)
"""

import logging
from pathlib import Path
from typing import Optional, Tuple, Union

import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def load_raw_data(data_path: Union[str, Path]) -> pd.DataFrame:
    """Load CIC-IDS2017 CSV file(s) from a file or directory path.

    Args:
        data_path: Path to a CSV file or directory containing CSV files.

    Returns:
        pd.DataFrame: Combined raw dataframe with stripped column names.
    """
    data_path = Path(data_path)

    if data_path.is_file():
        if not data_path.suffix.lower() == ".csv":
            raise ValueError(f"File {data_path} is not a CSV file.")
        logger.info(f"Loading single CSV dataset from {data_path}...")
        df = pd.read_csv(data_path, low_memory=False)
    elif data_path.is_dir():
        csv_files = sorted(list(data_path.glob("*.csv")))
        if not csv_files:
            raise FileNotFoundError(f"No CSV files found in directory {data_path}")
        logger.info(f"Found {len(csv_files)} CSV files in {data_path}. Loading and combining...")
        dfs = []
        for file in csv_files:
            logger.info(f"Reading {file.name}...")
            dfs.append(pd.read_csv(file, low_memory=False))
        df = pd.concat(dfs, ignore_index=True)
    else:
        raise FileNotFoundError(f"Data path not found: {data_path}")

    # Strip extra whitespace around header column names
    df.columns = df.columns.str.strip()
    logger.info(f"Raw data loaded successfully. Initial shape: {df.shape}")
    return df


def clean_data(df: pd.DataFrame, label_column: str = "Label") -> pd.DataFrame:
    """Clean raw dataset by handling infinite values, missing values, and duplicates.

    Args:
        df: Input raw DataFrame.
        label_column: Name of the target label column.

    Returns:
        pd.DataFrame: Cleaned DataFrame.
    """
    initial_rows = len(df)
    logger.info(f"Starting data cleaning on dataframe with {initial_rows} rows...")

    # 1. Clean string values in the label column if present
    if label_column in df.columns and df[label_column].dtype == "object":
        df[label_column] = df[label_column].astype(str).str.strip()

    # 2. Replace Inf and -Inf values with NaN across numeric features
    logger.info("Replacing Inf / -Inf values with NaN...")
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)

    # Also handle string column representations of Infinity if any
    object_cols = df.select_dtypes(include=["object"]).columns
    object_feature_cols = [c for c in object_cols if c != label_column]
    for c in object_feature_cols:
        df[c] = df[c].replace(["Infinity", "-Infinity", "inf", "-inf"], np.nan)
        # Attempt conversion to numeric for numeric features stored as strings
        df[c] = pd.to_numeric(df[c], errors="coerce")

    # 3. Remove NaN/null rows
    nan_rows_count = df.isna().any(axis=1).sum()
    logger.info(f"Removing {nan_rows_count} rows containing NaN / Inf values...")
    df = df.dropna().reset_index(drop=True)

    # 4. Remove duplicate rows
    duplicate_count = df.duplicated().sum()
    logger.info(f"Removing {duplicate_count} duplicate rows...")
    df = df.drop_duplicates().reset_index(drop=True)

    final_rows = len(df)
    removed_rows = initial_rows - final_rows
    logger.info(
        f"Data cleaning complete. Retained {final_rows}/{initial_rows} rows "
        f"(removed {removed_rows} rows, {removed_rows / initial_rows:.2%})."
    )

    return df


def encode_labels(
    df: pd.DataFrame, label_column: str = "Label"
) -> Tuple[pd.DataFrame, LabelEncoder]:
    """Label-encode target attack type strings into integers.

    Args:
        df: Cleaned DataFrame with target label column.
        label_column: Name of the label column to encode.

    Returns:
        Tuple[pd.DataFrame, LabelEncoder]: DataFrame with encoded label column and fitted LabelEncoder.
    """
    if label_column not in df.columns:
        raise KeyError(f"Label column '{label_column}' not found in DataFrame.")

    df = df.copy()
    encoder = LabelEncoder()

    logger.info(f"Encoding label column '{label_column}'...")
    df[label_column] = encoder.fit_transform(df[label_column])

    # Log encoding mapping
    mapping = dict(zip(encoder.classes_, encoder.transform(encoder.classes_)))
    logger.info(f"Label encoding mapping established ({len(mapping)} classes): {mapping}")

    return df, encoder


def preprocess_pipeline(
    data_path: Union[str, Path] = "data",
    label_column: str = "Label",
    save_processed: bool = False,
    output_path: Optional[Union[str, Path]] = None,
) -> Tuple[pd.DataFrame, LabelEncoder]:
    """Execute full preprocessing pipeline: load -> clean -> label encode -> (optional save).

    Args:
        data_path: Path to dataset file or folder (defaults to 'data').
        label_column: Name of the attack label column.
        save_processed: Whether to save the preprocessed data to disk.
        output_path: Destination path for cleaned dataset if save_processed is True.

    Returns:
        Tuple[pd.DataFrame, LabelEncoder]: Preprocessed DataFrame and the fitted LabelEncoder.
    """
    df_raw = load_raw_data(data_path)
    df_clean = clean_data(df_raw, label_column=label_column)
    df_encoded, encoder = encode_labels(df_clean, label_column=label_column)

    if save_processed:
        if output_path is None:
            output_dir = Path(data_path).parent if Path(data_path).is_file() else Path(data_path)
            processed_dir = output_dir / "processed"
            processed_dir.mkdir(parents=True, exist_ok=True)
            output_path = processed_dir / "CICIDS2017_cleaned.csv"
        else:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)

        logger.info(f"Saving preprocessed data to {output_path}...")
        df_encoded.to_csv(output_path, index=False)
        logger.info("Saved preprocessed dataset successfully.")

    return df_encoded, encoder


if __name__ == "__main__":
    # Example execution on data directory
    project_root = Path(__file__).resolve().parent.parent
    data_dir = project_root / "data"

    if (data_dir / "CICIDS2017_Combined.csv").exists():
        target_path = data_dir / "CICIDS2017_Combined.csv"
    else:
        target_path = data_dir

    logger.info(f"Executing preprocessing pipeline on target path: {target_path}")
    df_processed, label_encoder = preprocess_pipeline(
        data_path=target_path,
        save_processed=False
    )
    logger.info(f"Pipeline executed successfully. Final processed shape: {df_processed.shape}")
