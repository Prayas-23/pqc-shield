"""Intrusion detectors.

Will wrap the ML detectors under test (scikit-learn models and a small PyTorch
model) behind one typed fit/predict interface, with fixed seeds and source-aware
train/test splits that never mix sources unless explicitly requested.
"""
