sudo -E ig image list

cat gadgets/trace_dns.go
cat gadgets/rust/trace_dns.rs

sudo -E ig image build --dir ./gadgets/trace_dns-v1 albantest.azurecr.io/trace-dns:v1
sudo -E ig image push albantest.azurecr.io/trace-dns:v1
sudo -E ig image build --dir ./gadgets/trace_dns-v2 albantest.azurecr.io/trace-dns:v2
sudo -E ig image push albantest.azurecr.io/trace-dns:v2
sudo -E ig image build --dir ./gadgets/trace_dns-v3 albantest.azurecr.io/trace-dns:v3
sudo -E ig image push albantest.azurecr.io/trace-dns:v3

sudo -E ig image list

sudo -E ig run albantest.azurecr.io/trace-dns:v1
sudo -E ig run albantest.azurecr.io/trace-dns:v2
sudo -E ig run albantest.azurecr.io/trace-dns:v3

