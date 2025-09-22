# train_url_model.py
"""
Robust training script for URL phishing classifier.

Features:
 - Accepts --label-col to specify which CSV column contains labels (e.g. "Label")
 - Accepts --auto-label to label dataset using url_rules.analyze_url() heuristics
 - Works if kagglehub.dataset_download returns an archive OR an already-extracted directory
 - Robust CSV reading with several encodings, tolerant parsing for TXT
 - Saves bundle to provided output path (joblib)

Usage examples:
  python3 train_url_model.py --folder kaggle_extracted --label-col Label --out models/url_phish_model.joblib
  python3 train_url_model.py --folder kaggle_extracted --auto-label --out models/url_phish_model.joblib
  python3 train_url_model.py --dataset "owner/dataset" --label-col Label --out models/url_phish_model.joblib
"""
import argparse
import os
import sys
import tempfile
import zipfile
from pathlib import Path
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, roc_auc_score
from sklearn.preprocessing import StandardScaler
from scipy.sparse import hstack, csr_matrix
import joblib
import json
import re

from url_rules import analyze_url, RULES

# optional kagglehub (if using --dataset)
try:
    import kagglehub
    KAGGLEHUB_AVAILABLE = True
except Exception:
    KAGGLEHUB_AVAILABLE = False

# -------------------------------------------------------------------
# Helper: discover candidate files
# -------------------------------------------------------------------
def find_candidate_files(root):
    root = Path(root)
    cands = list(root.rglob("*.csv")) + list(root.rglob("*.txt"))
    return [str(p) for p in cands]

# -------------------------------------------------------------------
# Helper: robust file loader with optional explicit label column
# -------------------------------------------------------------------
POSITIVE_TOKENS = {'bad','phish','phishing','malicious','malware','1','true','t','yes','y'}

def _map_label_value(v):
    if pd.isna(v):
        return np.nan
    s = str(v).strip().lower()
    # handle numeric strings
    if re.fullmatch(r'0|1', s):
        return int(s)
    # map known tokens
    if any(tok == s for tok in POSITIVE_TOKENS):
        return 1
    # also handle 'legit','good','benign' as 0
    if any(s == t for t in ('legit','good','benign','clean','0','no','false','f')):
        return 0
    # otherwise treat unknown as NaN (we'll drop later unless auto-label chosen)
    return np.nan

def load_urls_from_file(path, label_col=None, auto_label=False):
    """
    Load urls and labels from a CSV or TXT.
    - label_col: explicit column name to use (case-sensitive)
    - auto_label: if True and no label column found, will label using heuristics
    Returns DataFrame with columns ['url','label'] where label may be NaN.
    """
    p = Path(path)
    if p.suffix.lower() == ".csv":
        df0 = None
        for enc in ("utf-8", "latin-1", "cp1252"):
            try:
                df0 = pd.read_csv(p, dtype=str, encoding=enc, engine='python')
                break
            except Exception:
                df0 = None
        if df0 is None:
            print("Failed to read CSV:", path)
            return pd.DataFrame(columns=['url','label'])
        # normalize columns lookup
        cols_lower = [c.lower() for c in df0.columns]
        # Determine URL column
        url_col = None
        # if user provided label_col only, url likely is 'URL' or similar; try common ones
        candidates_url = ("url","link","uri","site","website","phish_url","phishing_url","website_url")
        for i,c in enumerate(cols_lower):
            if c in candidates_url or any(k in c for k in candidates_url):
                url_col = df0.columns[i]
                break
        # fallback: first column
        if url_col is None:
            url_col = df0.columns[0]
        # Determine label column: priority to explicit label_col arg
        chosen_label_col = None
        if label_col:
            if label_col in df0.columns:
                chosen_label_col = label_col
            else:
                # try case-insensitive match
                for c in df0.columns:
                    if c.lower() == label_col.lower():
                        chosen_label_col = c
                        break
        if chosen_label_col is None:
            # heuristics to find likely label column
            for i,c in enumerate(cols_lower):
                if any(k in c for k in ("label","class","status","type","is_phish","phishing")):
                    chosen_label_col = df0.columns[i]
                    break
        # Build output df
        out = pd.DataFrame()
        out['url'] = df0[url_col].astype(str).str.strip()
        if chosen_label_col is not None:
            raw_labels = df0[chosen_label_col]
            mapped = raw_labels.map(_map_label_value)
            out['label'] = mapped
        else:
            out['label'] = np.nan
            if auto_label:
                # compute labels via heuristics later in caller
                pass
        return out

    else:
        # TXT-like simple loader
        rows = []
        with open(p, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if ',' in line and line.count(',') <= 3:
                    parts = [x.strip() for x in line.split(',')]
                    # heuristic: choose token that looks like url
                    url = None
                    for t in parts:
                        if t.startswith('http') or ('.' in t and ' ' not in t):
                            url = t
                            break
                    url = url or parts[-1]
                    lab_guess = parts[0] if parts[0] != url else (parts[1] if len(parts) > 1 else '')
                    label = _map_label_value(lab_guess)
                    rows.append((url, label))
                else:
                    rows.append((line, np.nan))
        if not rows:
            return pd.DataFrame(columns=['url','label'])
        df = pd.DataFrame(rows, columns=['url','label'])
        return df

# -------------------------------------------------------------------
# Feature extraction
# -------------------------------------------------------------------
def rules_features(urls):
    feat_names = [r[0] for r in RULES]
    X = []
    for u in urls:
        r = analyze_url(u)
        details = r.get('details', {})
        row = [1 if details.get(n, False) else 0 for n in feat_names]
        X.append(row)
    return np.array(X, dtype=int), feat_names

# -------------------------------------------------------------------
# Training pipeline
# -------------------------------------------------------------------
def train_from_folder(folder, out_path, label_col=None, auto_label=False, test_size=0.2, random_state=42):
    folder = Path(folder)
    if not folder.exists():
        raise RuntimeError("Folder not found: " + str(folder))
    cand = find_candidate_files(folder)
    if not cand:
        raise RuntimeError("No CSV/TXT dataset files found in folder: " + str(folder))
    print("Found candidate dataset files:", len(cand))
    dfs = []
    for f in cand:
        try:
            d = load_urls_from_file(f, label_col=label_col, auto_label=auto_label)
            if d is not None and not d.empty:
                print("Loaded", f, "-> rows:", len(d))
                dfs.append(d)
        except Exception as e:
            print("Failed to load", f, e)
    if not dfs:
        raise RuntimeError("No usable data frames loaded from dataset files")
    df = pd.concat(dfs, ignore_index=True)
    df['url'] = df['url'].astype(str).str.strip()
    df = df[df['url'].notna() & (df['url'] != '')]
    df = df.drop_duplicates(subset=['url']).reset_index(drop=True)

    # If no labels present and auto_label is True -> compute
    if df['label'].isna().all():
        if auto_label:
            print("No labels detected — auto-labeling using heuristics (url_rules.analyze_url())")
            df['label'] = df['url'].map(lambda u: int(analyze_url(u).get('label', 0)))
        else:
            raise RuntimeError("Dataset did not contain labels. Provide labeled data (url,label) or use --auto-label to auto-label with heuristics.")

    # If mixed labels with NaN, drop unlabeled rows
    if df['label'].isna().any():
        before = len(df)
        df = df[df['label'].notna()].copy()
        print(f"Dropping {before - len(df)} rows with missing labels; {len(df)} remain.")

    df['label'] = df['label'].astype(int)
    pos = int(df['label'].sum())
    print("Final dataset rows:", len(df), "positives:", pos, "negatives:", len(df)-pos)

    if pos == 0 or pos == len(df):
        print("Warning: dataset contains only one class after processing. Training will fail. Consider using --auto-label or provide proper labels.")
        if not auto_label:
            raise RuntimeError("Need at least two classes for training. Use --auto-label or supply a dataset with both classes.")

    urls = df['url'].tolist()
    X_rules, feat_names = rules_features(urls)

    tf = TfidfVectorizer(analyzer='char_wb', ngram_range=(3,5), max_features=20000)
    X_tfidf = tf.fit_transform(urls)

    scaler = StandardScaler(with_mean=False)
    X_rules_scaled = scaler.fit_transform(X_rules)

    X = hstack([csr_matrix(X_rules_scaled), X_tfidf])
    y = df['label'].values

    # train/test split (stratify if there are at least 2 classes)
    stratify = y if len(np.unique(y)) > 1 else None
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=random_state, stratify=stratify)

    # model
    clf = LogisticRegression(max_iter=2000, class_weight='balanced', solver='liblinear')
    print("Training model...")
    clf.fit(X_train, y_train)

    # evaluate
    y_pred = clf.predict(X_test)
    try:
        y_proba = clf.predict_proba(X_test)[:,1]
    except Exception:
        y_proba = None
    acc = accuracy_score(y_test, y_pred)
    try:
        auc = roc_auc_score(y_test, y_proba) if y_proba is not None else None
    except Exception:
        auc = None
    print("Test accuracy: {:.4f}".format(acc))
    if auc is not None:
        print("Test AUC: {:.4f}".format(auc))
    print("Classification report:")
    print(classification_report(y_test, y_pred))

    bundle = {'model': clf, 'tfidf': tf, 'scaler': scaler, 'rules_features': feat_names}
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    joblib.dump(bundle, out_path)
    print("Saved model bundle to", out_path)
    return bundle

# -------------------------------------------------------------------
# CLI
# -------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Train URL phishing classifier (rules + TF-IDF).")
    parser.add_argument('--dataset', help='KaggleHub dataset id (owner/dataset)')
    parser.add_argument('--folder', help='Local folder (unzipped dataset)')
    parser.add_argument('--label-col', help='Explicit CSV column name to use as label (e.g. Label)', default=None)
    parser.add_argument('--auto-label', help='If set, auto-label dataset using heuristics when labels missing', action='store_true')
    parser.add_argument('--out', help='Output joblib path', default='models/url_phish_model.joblib')
    parser.add_argument('--test-size', type=float, default=0.2)
    args = parser.parse_args()

    folder = None
    tmpdir = None

    if args.dataset:
        if not KAGGLEHUB_AVAILABLE:
            print("kagglehub not available. Install with: pip install kagglehub")
            sys.exit(1)
        print("Downloading via kagglehub:", args.dataset)
        downloaded = kagglehub.dataset_download(args.dataset)
        print("Downloaded:", downloaded)
        if os.path.isdir(downloaded):
            folder = downloaded
        else:
            tmpdir = tempfile.TemporaryDirectory()
            try:
                if zipfile.is_zipfile(downloaded):
                    with zipfile.ZipFile(downloaded, 'r') as z:
                        z.extractall(tmpdir.name)
                        folder = tmpdir.name
                else:
                    import tarfile
                    if tarfile.is_tarfile(downloaded):
                        with tarfile.open(downloaded, 'r:*') as t:
                            t.extractall(tmpdir.name)
                            folder = tmpdir.name
                    else:
                        folder = os.path.dirname(downloaded)
            except Exception as e:
                print("Extraction failed:", e)
                folder = os.path.dirname(downloaded)
    elif args.folder:
        folder = args.folder
    else:
        print("Provide --dataset or --folder")
        sys.exit(1)

    if not folder:
        print("Could not determine dataset folder.")
        sys.exit(1)

    train_from_folder(folder, args.out, label_col=args.label_col, auto_label=args.auto_label, test_size=args.test_size)

    if tmpdir:
        tmpdir.cleanup()

if __name__ == '__main__':
    main()
