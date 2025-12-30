
import pandas as pd
import io
import requests
import logging

logger = logging.getLogger(__name__)

def clean_and_format_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Applies heuristic cleaning to a pandas DataFrame:
    1. Normalizes column names (lowercase, strip spaces, replace spaces with underscores).
    2. Drops completely empty rows and columns.
    3. Tries to infer correct data types (numeric, datetime).
    4. Fill NaN values with sensible defaults (optional, but skipping for now to keep data truthful).
    """
    # 1. Clean Headers
    if isinstance(df.columns[0], str): # Check if headers are strings
        df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_').str.replace('[^a-w0-9_]', '', regex=True)
    
    # 2. Drop empty
    df.dropna(how='all', axis=0, inplace=True) # Empty rows
    df.dropna(how='all', axis=1, inplace=True) # Empty cols

    # 3. Infer types
    # Attempt to convert object columns to numeric first
    for col in df.columns:
        # Try numeric
        try:
            df[col] = pd.to_numeric(df[col])
        except (ValueError, TypeError):
            # Try datetime if looks like date
            try:
                if df[col].dtype == 'object':
                     # simple check if enough chars to be a date
                     sample = df[col].dropna().iloc[0] if not df[col].dropna().empty else ""
                     if len(str(sample)) > 6: 
                        df[col] = pd.to_datetime(df[col], errors='ignore')
            except (ValueError, TypeError):
                pass
    
    return df

def load_data_from_url(url: str) -> pd.DataFrame:
    """
    Attempts to load a DataFrame from a URL. 
    Supports CSV and Excel files.
    """
    try:
        # Basic check for extension (not foolproof but good heuristic)
        lower_url = url.lower()
        
        # If it looks like a direct file connection (simple GET)
        # Note: In a real app, we need to handle auth, but here we assume public/accessible URLs.
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        content = io.BytesIO(response.content)

        if lower_url.endswith('.csv') or 'csv' in lower_url:
            return pd.read_csv(content)
        elif lower_url.endswith('.xlsx') or lower_url.endswith('.xls'):
            return pd.read_excel(content)
        else:
            # Fallback: Try CSV first, then Excel
            try:
                content.seek(0)
                return pd.read_csv(content)
            except:
                content.seek(0)
                return pd.read_excel(content)
                
    except Exception as e:
        logger.error(f"Data loading failed for {url}: {e}")
        return None
