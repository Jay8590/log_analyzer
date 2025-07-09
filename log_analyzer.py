import streamlit as st
import pandas as pd
import json
import re
from pathlib import Path
from datetime import datetime, timedelta
from fuzzywuzzy import fuzz
from fuzzywuzzy import process

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
    
    sample_timestamps = [ts for ts in timestamps if pd.notna(ts) and ts.strip()][:100]
    
    if not sample_timestamps:
        return None
    
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

def fuzzy_search_messages(df, search_term, threshold=70):
    if not search_term or df.empty:
        return df
    
    messages = df['message'].fillna('').astype(str)
    
    matches = []
    for idx, message in enumerate(messages):
        if message.strip(): 
            score = fuzz.partial_ratio(search_term.lower(), message.lower())
            if score >= threshold:
                matches.append((idx, score))
    
    if not matches:
        return pd.DataFrame(columns=df.columns)
    
    matches.sort(key=lambda x: x[1], reverse=True)
    indices = [match[0] for match in matches]
    
    result_df = df.iloc[indices].copy()
    result_df['fuzzy_score'] = [match[1] for match in matches]
    
    return result_df

def filter_logs(df, search_term, log_levels, selected_files, date_range, 
                time_range, selected_functions, selected_names, 
                use_fuzzy_search=False, fuzzy_threshold=70):
    filtered_df = df.copy()
    
    # File filtering
    if selected_files:
        filtered_df = filtered_df[filtered_df['source_file'].isin(selected_files)]
    
    # Log level filtering
    if log_levels:
        filtered_df = filtered_df[filtered_df['level'].isin(log_levels)]
    
    # Date range filtering
    if date_range and not filtered_df.empty:
        start_date, end_date = date_range
        if not filtered_df['timestamp'].empty:
            mask = (filtered_df['timestamp'].dt.date >= start_date) & (filtered_df['timestamp'].dt.date <= end_date)
            filtered_df = filtered_df[mask]
    
    # Time range filtering
    if time_range and not filtered_df.empty:
        start_time, end_time = time_range
        if not filtered_df['timestamp'].empty:
            mask = (filtered_df['timestamp'].dt.time >= start_time) & (filtered_df['timestamp'].dt.time <= end_time)
            filtered_df = filtered_df[mask]
    
    # Function filtering
    if selected_functions:
        filtered_df = filtered_df[filtered_df['function'].isin(selected_functions)]
    
    # Logger name filtering
    if selected_names:
        filtered_df = filtered_df[filtered_df['name'].isin(selected_names)]
    
    # Search term filtering (fuzzy or exact)
    if search_term:
        if use_fuzzy_search:
            filtered_df = fuzzy_search_messages(filtered_df, search_term, fuzzy_threshold)
        else:
            filtered_df = filtered_df[filtered_df['message'].str.contains(search_term, case=False, na=False)]
    
    return filtered_df

def get_log_stats(df):
    if df.empty:
        return {}
    
    stats = {
        'total_entries': len(df),
        'date_range': None,
        'level_distribution': df['level'].value_counts().to_dict(),
        'file_distribution': df['source_file'].value_counts().to_dict(),
        'top_functions': df['function'].value_counts().head(10).to_dict(),
        'top_loggers': df['name'].value_counts().head(10).to_dict(),
        'errors_count': len(df[df['level'] == 'ERROR']),
        'warnings_count': len(df[df['level'] == 'WARNING']),
    }
    
    if 'timestamp' in df.columns and not df['timestamp'].empty:
        valid_timestamps = df['timestamp'].dropna()
        if not valid_timestamps.empty:
            stats['date_range'] = (valid_timestamps.min(), valid_timestamps.max())
    
    return stats

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
    
    if uploaded_files:
        current_file_names = [file.name for file in uploaded_files]
        if not current_file_names:
            st.session_state.df = None
            st.session_state.processed_files = []
        elif set(current_file_names) != set(st.session_state.processed_files):
            st.session_state.df = None
            st.session_state.processed_files = []
    else:
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
                    st.session_state.processed_files = [f.name for f in valid_files]
                    st.success(f"Successfully loaded {len(all_logs)} log entries from {len(valid_files)} files.")
                else:
                    st.warning("No valid log entries found in the uploaded files.")
    
    if st.session_state.df is not None and not st.session_state.df.empty:
        df = st.session_state.df
        
        st.sidebar.markdown("---")
        st.sidebar.subheader("🔎 Advanced Filters")
        
        filter_tabs = st.sidebar.tabs(["Basic", "Advanced"])
        
        with filter_tabs[0]: 
            available_files = sorted(df['source_file'].unique())
            selected_files = st.multiselect(
                "Select files:",
                options=available_files,
                default=available_files,
                help="Filter by source file"
            )
            
            available_levels = sorted(df['level'].dropna().unique())
            selected_levels = st.multiselect(
                "Log levels:",
                options=available_levels,
                default=available_levels,
                help="Filter by log level"
            )
            
            st.markdown("**Search Configuration:**")
            use_fuzzy_search = st.checkbox(
                "Enable fuzzy search",
                value=False,
                help="Fuzzy search finds similar matches even with typos"
            )
            
            if use_fuzzy_search:
                fuzzy_threshold = st.slider(
                    "Fuzzy match threshold:",
                    min_value=50,
                    max_value=100,
                    value=70,
                    help="Higher values = more exact matches"
                )
            else:
                fuzzy_threshold = 70
            
            search_term = st.text_input(
                "Search in message:", 
                placeholder="Enter search term...",
                help="Search in log messages. Use fuzzy search for typo-tolerant matching."
            )
            
            if search_term and use_fuzzy_search:
                st.info(f"🔍 Fuzzy search enabled with {fuzzy_threshold}% threshold")
        
        with filter_tabs[1]:  
            date_range = None
            if 'timestamp' in df.columns and not df['timestamp'].empty:
                valid_timestamps = df['timestamp'].dropna()
                if not valid_timestamps.empty:
                    min_date = valid_timestamps.dt.date.min()
                    max_date = valid_timestamps.dt.date.max()
                    
                    use_date_filter = st.checkbox("Filter by date range")
                    if use_date_filter:
                        date_range = st.date_input(
                            "Select date range:",
                            value=(min_date, max_date),
                            min_value=min_date,
                            max_value=max_date
                        )
                        if isinstance(date_range, tuple) and len(date_range) == 2:
                            pass  # Valid range
                        else:
                            date_range = None
            
            time_range = None
            use_time_filter = st.checkbox("Filter by time range")
            if use_time_filter:
                start_time = st.time_input("Start time:", value=datetime.min.time())
                end_time = st.time_input("End time:", value=datetime.max.time())
                time_range = (start_time, end_time)
            
            available_functions = sorted(df['function'].dropna().unique())
            selected_functions = st.multiselect(
                "Filter by function:",
                options=available_functions,
                help="Filter by function name"
            )
            
            available_names = sorted(df['name'].dropna().unique())
            selected_names = st.multiselect(
                "Filter by logger name:",
                options=available_names,
                help="Filter by logger name"
            )
        
        
        filtered_df = filter_logs(
            df, search_term, selected_levels, selected_files, date_range,
            time_range, selected_functions, selected_names,
            use_fuzzy_search, fuzzy_threshold
        )
        
        if use_fuzzy_search and search_term and 'fuzzy_score' in filtered_df.columns:
            st.info(f"Showing {len(filtered_df)} fuzzy matches of {len(df)} total entries (threshold: {fuzzy_threshold}%)")
        else:
            st.info(f"Showing {len(filtered_df)} of {len(df)} total log entries based on filters.")
        
        st.subheader("📊 Statistics")
        stats = get_log_stats(filtered_df)
        
        metrics_cols = st.columns(4)
        with metrics_cols[0]:
            st.metric("Total Entries", stats.get('total_entries', 0))
        with metrics_cols[1]:
            st.metric("Error Count", stats.get('errors_count', 0))
        with metrics_cols[2]:
            st.metric("Warning Count", stats.get('warnings_count', 0))
        with metrics_cols[3]:
            st.metric("Files", len(selected_files))
        
        st.subheader("📋 Detailed Log Entries")
        
        display_cols = st.columns([3, 1])
        with display_cols[0]:
            default_columns = ['timestamp', 'level', 'message', 'source_file']
            if use_fuzzy_search and search_term and 'fuzzy_score' in filtered_df.columns:
                default_columns.append('fuzzy_score')
            
            available_columns = ['timestamp', 'level', 'message', 'source_file', 'function', 'filename', 'line_number', 'name']
            if 'fuzzy_score' in filtered_df.columns:
                available_columns.append('fuzzy_score')
            
            show_columns = st.multiselect(
                "Select columns to display:",
                options=available_columns,
                default=default_columns
            )
        with display_cols[1]:
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
            
            if 'fuzzy_score' in display_df.columns:
                display_df = display_df.copy()
                display_df['fuzzy_score'] = display_df['fuzzy_score'].apply(lambda x: f"{x}%" if pd.notna(x) else "")
            
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