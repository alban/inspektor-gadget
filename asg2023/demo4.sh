kubectl get pod -n falco
kubectl get configmap -n falco falco -o yaml | grep -B1 'name: ig'
cat ig_rules.yaml

kubectl logs $(kubectl get pod -n falco -o name) -n falco

