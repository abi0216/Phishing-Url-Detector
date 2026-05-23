import pandas as pd
import numpy as np
from feature_extraction import extract_features
import os
from tqdm import tqdm

def prepare():
    input_path = os.path.join("datasets", "final_dataset.csv")
    output_path = os.path.join("datasets", "featured_25_dataset.csv")
    
    print(f"Loading {input_path}...")
    df = pd.read_csv(input_path)
    
    # Increase sample size for high accuracy (100k rows)
    sample_size = min(len(df), 100000)
    df = df.sample(n=sample_size, random_state=42)
    
    print(f"Extracting 25 high-accuracy features for {sample_size} URLs...")
    
    feature_list = []
    targets = []
    
    for _, row in tqdm(df.iterrows(), total=len(df)):
        url = str(row['url'])
        target = row['label']
        
        # Extract the new 25 numerical features
        feats, _ = extract_features(url, include_external=False)
        
        feature_list.append(feats)
        targets.append(target)
    
    from feature_extraction import FEATURE_NAMES
    new_df = pd.DataFrame(feature_list, columns=FEATURE_NAMES)
    new_df['target'] = targets
    
    new_df.to_csv(output_path, index=False)
    print(f"Saved optimized dataset to {output_path}")

if __name__ == "__main__":
    prepare()
