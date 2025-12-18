import numpy as np
import pandas as pd

from sklearn.base import BaseEstimator,TransformerMixin


class DropAndClip(BaseEstimator, TransformerMixin):
    def __init__(self, leakage_cols=None, clip_cols=None, upper_quantile=0.999, log_transform=True):
        self.leakage_cols = leakage_cols or []
        self.clip_cols = clip_cols or []
        self.upper_quantile = upper_quantile
        self.log_transform = log_transform

    def fit(self, X, y=None):
        if isinstance(X, np.ndarray):
            X = pd.DataFrame(X)
        X2 = X.copy()
        X2 = X2.drop(columns=[c for c in self.leakage_cols if c in X2.columns], errors='ignore')
        self.clip_cols_ = [c for c in self.clip_cols if c in X2.columns]
        if self.clip_cols_:
            self.upper_ = X2[self.clip_cols_].quantile(self.upper_quantile).to_dict()
        else:
            self.upper_ = {}
        return self

    def transform(self, X):
        if isinstance(X, np.ndarray):
            X = pd.DataFrame(X)
        X2 = X.copy()
        X2 = X2.drop(columns=[c for c in self.leakage_cols if c in X2.columns], errors='ignore')
        for c in self.clip_cols_:
            if c in X2.columns:
                val = np.minimum(X2[c], self.upper_[c])
                if self.log_transform:
                    X2[c + '_log'] = np.log1p(val)
                else:
                    X2[c + '_clipped'] = val
                X2 = X2.drop(columns=[c])
        return X2