# Core Imports
import sys
import os
import pandas as pd
import numpy as np
from tqdm import tqdm

# Robust Path Injection
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from feature_extraction import extract_features, FEATURE_NAMES

def generate_ultra_dataset():
    input_path = os.path.join(os.path.dirname(__file__), 'balanced_urls.csv')
    output_path = os.path.join(os.path.dirname(__file__), 'featured_40_dataset.csv')
    
    if not os.path.exists(input_path):
        print(f"Error: {input_path} not found.")
        return

    print(f"Reading raw data from {input_path}...")
    df = pd.read_csv(input_path)
    
    # Take a large sample for better accuracy while keeping preparation time reasonable
    sample_size = 200000
    if len(df) > sample_size:
        print(f"Sampling {sample_size} URLs for training...")
        df = df.sample(n=sample_size, random_state=42)
    
    X = []
    y = []
    
    print(f"Extracting 40 features for {len(df)} URLs...")
    for index, row in tqdm(df.iterrows(), total=len(df)):
        url = str(row['url'])
        label = row['result'] 
        
        try:
            features, _ = extract_features(url, include_external=False)
            if len(features) == 40:
                X.append(features)
                y.append(label)
        except:
            continue
            
    # Create new DataFrame
    featured_df = pd.DataFrame(X, columns=FEATURE_NAMES)
    featured_df['target'] = y
    
    print(f"Saving ultra dataset with {len(featured_df)} samples to {output_path}...")
    featured_df.to_csv(output_path, index=False)
    print("Generation Complete.")

if __name__ == "__main__":
    generate_ultra_dataset()
