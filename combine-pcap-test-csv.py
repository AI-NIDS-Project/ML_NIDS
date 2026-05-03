import pandas as pd

x_recon_nmap = pd.read_csv("./pcap-test-csv/x_recon_nmap.csv")
y_recon_nmap = pd.read_csv("./pcap-test-csv/y_recon_nmap.csv")
x_recon_sCsV = pd.read_csv("./pcap-test-csv/x_recon_sCsV.csv")
y_recon_sCsV = pd.read_csv("./pcap-test-csv/y_recon_sCsV.csv")
x_dos_synflood = pd.read_csv("./pcap-test-csv/x_dos_synflood.csv")
y_dos_synflood = pd.read_csv("./pcap-test-csv/y_dos_synflood.csv")
x_brute_hydraftp = pd.read_csv("./pcap-test-csv/x_brute_hydraftp.csv")
y_brute_hydraftp = pd.read_csv("./pcap-test-csv/y_brute_hydraftp.csv")
x_brute_hydrassh = pd.read_csv("./pcap-test-csv/x_brute_hydrassh.csv")
y_brute_hydrassh = pd.read_csv("./pcap-test-csv/y_brute_hydrassh.csv")

df_recon_nmap = pd.concat([x_recon_nmap, y_recon_nmap], axis=1)
df_recon_sCsV = pd.concat([x_recon_sCsV, y_recon_sCsV], axis=1)
df_dos_synflood = pd.concat([x_dos_synflood, y_dos_synflood], axis=1)
df_brute_hydraftp = pd.concat([x_brute_hydraftp, y_brute_hydraftp], axis=1)
df_brute_hydrassh = pd.concat([x_brute_hydrassh, y_brute_hydrassh], axis=1)

df_recon_nmap.to_csv("./pcap-test-csv/df_recon_nmap.csv", index=False)
df_recon_sCsV.to_csv("./pcap-test-csv/df_recon_sCsV.csv", index=False)
df_dos_synflood.to_csv("./pcap-test-csv/df_dos_synflood.csv", index=False)
df_brute_hydraftp.to_csv("./pcap-test-csv/df_brute_hydraftp.csv", index=False)
df_brute_hydrassh.to_csv("./pcap-test-csv/df_brute_hydrassh.csv", index=False)