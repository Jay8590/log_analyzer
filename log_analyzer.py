import streamlit as st
import pandas as pd
import json
import re
from pathlib import Path

def parse_log_line(line):
    try:
        if line.strip().startswith('{') and line.strip().endswith('}'):
            log_data = json.loads(line)
            return {
                'timestamp': log_data.get('asctime', ''),
                'level': log_data.get('levelname', ''),
                'name': log_data.get('name', ''),
                'message': log_data.get('message', ''),
                'filename': log_data.get('filename', ''),
                'function': log_data.get('funcName', ''),
                'line_number': log_data.get('lineno', None)
            }
        else:
            timestamp_match = re.search(r'"asctime": "([^"]+)"', line)
            level_match = re.search(r'"levelname": "([^"]+)"', line)
            name_match = re.search(r'"name": "([^"]+)"', line)
            message_match = re.search(r'"message": "([^"]+)"', line)
            filename_match = re.search(r'"filename": "([^"]+)"', line)
            funcname_match = re.search(r'"funcName": "([^"]+)"', line)
            lineno_match = re.search(r'"lineno": (\d+)', line)
            
            return {
                'timestamp': timestamp_match.group(1) if timestamp_match else None,
                'level': level_match.group(1) if level_match else None,
                'name': name_match.group(1) if name_match else None,
                'message': message_match.group(1) if message_match else None,
                'filename': filename_match.group(1) if filename_match else None,
                'function': funcname_match.group(1) if funcname_match else None,
                'line_number': int(lineno_match.group(1)) if lineno_match else None
            }
    except Exception as e:
        return None

def is_log_file(filename):
    filename_lower = filename.lower()
    
    if filename_lower.endswith(('.log', '.txt')):
        return True
    
    if re.match(r'.*\.log\.\d+$', filename_lower):
        return True
    
    if re.match(r'.*\.txt\.\d+$', filename_lower):
        return True
    
    return False

def infer_timestamp_format(timestamps):
    common_formats = [
        '%Y-%m-%d %H:%M:%S,%f',  # 2023-12-25 10:30:45,123
        '%Y-%m-%d %H:%M:%S.%f',  # 2023-12-25 10:30:45.123456
        '%Y-%m-%d %H:%M:%S',     # 2023-12-25 10:30:45
        '%d/%m/%Y %H:%M:%S',     # 25/12/2023 10:30:45
        '%m/%d/%Y %H:%M:%S',     # 12/25/2023 10:30:45
        '%Y-%m-%dT%H:%M:%S.%fZ', # 2023-12-25T10:30:45.123456Z
        '%Y-%m-%dT%H:%M:%SZ',    # 2023-12-25T10:30:45Z
        '%Y-%m-%dT%H:%M:%S',     # 2023-12-25T10:30:45
        '%a %b %d %H:%M:%S %Y',  # Mon Dec 25 10:30:45 2023
    ]
    
    # Sample up to 100 non-null timestamps for format detection
    sample_timestamps = [ts for ts in timestamps if pd.notna(ts) and ts.strip()][:100]
    
    if not sample_timestamps:
        return None
    
    # Try each format and count successful parses
    best_format = None
    best_count = 0
    
    for fmt in common_formats:
        count = 0
        for ts in sample_timestamps:
            try:
                pd.to_datetime(ts, format=fmt)
                count += 1
            except:
                continue
        
        if count > best_count:
            best_count = count
            best_format = fmt
    
    # Only return format if it works for at least 50% of samples
    if best_count >= len(sample_timestamps) * 0.5:
        return best_format
    
    return None

def parse_timestamps_efficiently(df):
    if 'timestamp' not in df.columns or df['timestamp'].empty:
        return df
    
    timestamp_format = infer_timestamp_format(df['timestamp'])
    
    if timestamp_format:
        try:
            df['timestamp'] = pd.to_datetime(df['timestamp'], format=timestamp_format, errors='coerce')
        except:
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    else:
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    
    return df

def filter_logs(df, search_term, log_levels):
    filtered_df = df.copy()
    
    if log_levels:
        filtered_df = filtered_df[filtered_df['level'].isin(log_levels)]
    
    if search_term:
        filtered_df = filtered_df[filtered_df['message'].str.contains(search_term, case=False, na=False)]
        
    return filtered_df

def main():
    st.set_page_config(page_title="Log Analyzer", layout="wide")
    st.title("🛠️ Log Analyzer")
    
    if 'df' not in st.session_state:
        st.session_state.df = None
    if 'processed_files' not in st.session_state:
        st.session_state.processed_files = []

    st.sidebar.title("Configuration")
    
    st.sidebar.subheader("📁 Upload Log Files")
    
    uploaded_files = st.sidebar.file_uploader(
        "Upload log files", 
        type=None,  
        accept_multiple_files=True,
        help="Select log files (.log, .txt, .log.1, .log.2, etc.)"
    )
    
    # Check if files were removed and update accordingly
    if uploaded_files:
        current_file_names = [file.name for file in uploaded_files]
        
        # If no files are uploaded, reset everything
        if not current_file_names:
            st.session_state.df = None
            st.session_state.processed_files = []
        # If some files were removed, check if we need to reprocess
        elif set(current_file_names) != set(st.session_state.processed_files):
            # Files have changed, need to reprocess
            st.session_state.df = None
            st.session_state.processed_files = []
    else:
        # No files uploaded, reset everything
        st.session_state.df = None
        st.session_state.processed_files = []
    
    if uploaded_files:
        valid_files = []
        invalid_files = []
        
        for file in uploaded_files:
            if is_log_file(file.name):
                valid_files.append(file)
            else:
                invalid_files.append(file.name)
        
        if invalid_files:
            st.sidebar.warning(f"⚠️ Skipping non-log files: {', '.join(invalid_files)}")
        
        if valid_files:
            st.sidebar.success(f"✅ Found {len(valid_files)} valid log files")
            
            with st.sidebar.expander("📋 Valid Files"):
                for file in valid_files:
                    st.write(f"• {file.name}")
        
        # Only process if we don't have data or if files have changed
        if valid_files and st.session_state.df is None:
            with st.spinner("Processing uploaded files..."):
                all_logs = []
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                for i, uploaded_file in enumerate(valid_files):
                    try:
                        status_text.text(f"Processing: {uploaded_file.name} ({i+1}/{len(valid_files)})")
                        
                        content = uploaded_file.read()
                        
                        try:
                            content = content.decode('utf-8')
                        except UnicodeDecodeError:
                            content = content.decode('latin-1', errors='ignore')
                        
                        log_lines = content.strip().split('\n')
                        
                        file_logs = []
                        for line_num, line in enumerate(log_lines, 1):
                            if line.strip():
                                parsed_log = parse_log_line(line)
                                if parsed_log:
                                    parsed_log['source_file'] = uploaded_file.name
                                    parsed_log['source_path'] = uploaded_file.name
                                    parsed_log['line_in_file'] = line_num
                                    file_logs.append(parsed_log)
                        
                        all_logs.extend(file_logs)
                        
                        progress_bar.progress((i + 1) / len(valid_files))
                        
                    except Exception as e:
                        st.error(f"Error processing {uploaded_file.name}: {str(e)}")
                
                status_text.text("Processing complete!")
                
                if all_logs:
                    st.session_state.df = pd.DataFrame(all_logs)
                    st.session_state.df = parse_timestamps_efficiently(st.session_state.df)
                    # Update processed files list to match current valid files
                    st.session_state.processed_files = [f.name for f in valid_files]
                    st.success(f"Successfully loaded {len(all_logs)} log entries from {len(valid_files)} files.")
                else:
                    st.warning("No valid log entries found in the uploaded files.")
    
    if st.session_state.df is not None and not st.session_state.df.empty:
        df = st.session_state.df
        st.sidebar.markdown("---")
        st.sidebar.subheader("🔎 Filter Logs")
        
        search_term = st.sidebar.text_input(
            "Search in message:", 
            placeholder="Enter search term...",
            help="Case-insensitive search in the log message"
        )
        
        available_levels = sorted(df['level'].dropna().unique())
        selected_levels = st.sidebar.multiselect(
            "Log levels:",
            options=available_levels,
            default=available_levels,
            help="Filter by log level"
        )
        
        filtered_df = filter_logs(df, search_term, selected_levels)
        
        st.info(f"Showing {len(filtered_df)} of {len(df)} total log entries based on filters.")
        
        st.subheader("📊 Summary")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Entries", len(df))
        with col2:
            st.metric("Filtered Entries", len(filtered_df))
        with col3:
            st.metric("Files Processed", len(st.session_state.processed_files))
        with col4:
            if not df.empty:
                unique_levels = len(df['level'].dropna().unique())
                st.metric("Log Levels", unique_levels)
        
        st.subheader("📋 Detailed Log Entries")
        
        col1, col2 = st.columns([3, 1])
        with col1:
            show_columns = st.multiselect(
                "Select columns to display:",
                options=['timestamp', 'level', 'message', 'source_file', 'function', 'filename', 'line_number', 'name'],
                default=['timestamp', 'level', 'message', 'source_file']
            )
        with col2:
            rows_per_page = st.selectbox("Rows per page:", [25, 50, 100, 200, 500], index=1)

        if show_columns and not filtered_df.empty:
            total_rows = len(filtered_df)
            total_pages = (total_rows - 1) // rows_per_page + 1
            
            page = 1
            if total_pages > 1:
                page = st.number_input("Page", min_value=1, max_value=total_pages, value=1, step=1)
            
            start_idx = (page - 1) * rows_per_page
            end_idx = start_idx + rows_per_page
            display_df = filtered_df.iloc[start_idx:end_idx]
            
            st.dataframe(
                display_df[show_columns],
                use_container_width=True,
                hide_index=True
            )
            
            if total_pages > 1:
                st.write(f"Showing page {page} of {total_pages} ({len(filtered_df)} total matching entries)")
        elif filtered_df.empty:
             st.warning("No logs match the current filters.")
        else:
            st.warning("Please select at least one column to display.")

    else:
        st.info("Please upload log files to begin analysis.")

if __name__ == "__main__":
    main()