sudo -E ig image build --dir ./gadgets/trace_dns-v1 albantest.azurecr.io/trace-dns:v1
sudo -E ig image push albantest.azurecr.io/trace-dns:v1
sudo -E ig image list

kubectl gadget run albantest.azurecr.io/trace-dns:v1 --podname shell01

nslookup -type=a wikipedia.org


sudo -E ig trace open --host --show-systemd

sudo systemd-run -t --unit=test01.service bash -c 'while sleep 1 ; do date ; done'
sudo -E ig trace open --host --show-systemd --sdunit test01.service

sudo systemctl start sshd
sudo -E ig trace open --host --show-systemd --sdunit sshd.service
