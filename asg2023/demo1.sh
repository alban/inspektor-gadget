sudo -E ig image list
sudo -E ig image build --dir ./gadgets/trace_tcpconnect albantest.azurecr.io/trace-tcpconnect:v1
sudo -E ig image list
sudo -E ig image push albantest.azurecr.io/trace-tcpconnect:v1
sudo -E ig run albantest.azurecr.io/trace-tcpconnect:v1 -c netem

kubectl gadget run albantest.azurecr.io/trace-tcpconnect:v1 --podname shell01

