# models/

Trained scikit-learn models are stored in the per-user data folder (`%APPDATA%\OfflineIDS\models`).
This folder holds optional training material:

* `labeled_training.csv` (optional) — columns: `packet_rate, byte_rate, connection_count, new_flow_rate, dport_diversity,
  syn_ratio, failed_logins, process_creation_rate, file_mod_rate, outbound_conn_freq, label` (`0` benign, `1` attack).
  Point **Threat Detection → Train Random Forest** at this file. Use only data captured from systems you own or are authorised to test.