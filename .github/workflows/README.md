# Inspektor Gadget CI Workflow

## Run integration tests on an ARO cluster

### Create the cluster

The following instructions describe how to create an [Azure Red Hat OpenShift
(ARO)](https://docs.microsoft.com/en-us/azure/openshift/intro-openshift) cluster
so that the `Inspektor Gadget CI` workflow will run the integration tests on it.

These are the steps to create the cluster using the CLI:

```bash
$ export SUBSCRIPTION=<mySubscription>
$ export RESOURCEGROUP=<myResourceName>
$ export LOCATION=<myLocation>
$ export CLUSTER=<myCluster>
$ export VNET=<myVNET>
$ export MASTSUB=<myMASTSUB>
$ export WORKSUB=<myWORKSUB>

# Set subscription so that we don't need to specify it at every command
$ az account set --subscription $SUBSCRIPTION

# Register resource providers
$ az provider register -n Microsoft.RedHatOpenShift --wait
$ az provider register -n Microsoft.Compute --wait
$ az provider register -n Microsoft.Storage --wait
$ az provider register -n Microsoft.Authorization --wait

# Create resource group
$ az group create --name $RESOURCEGROUP --location $LOCATION

# Create virtual network and two empty subnets for the master and the worker nodes.
$ az network vnet create --resource-group $RESOURCEGROUP --name $VNET --address-prefixes 10.0.0.0/22
$ az network vnet subnet create --resource-group $RESOURCEGROUP --vnet-name $VNET --name $MASTSUB --address-prefixes 10.0.0.0/23 --service-endpoints Microsoft.ContainerRegistry
$ az network vnet subnet create --resource-group $RESOURCEGROUP --vnet-name $VNET --name $WORKSUB --address-prefixes 10.0.2.0/23 --service-endpoints Microsoft.ContainerRegistry
$ az network vnet subnet update --name $MASTSUB --resource-group $RESOURCEGROUP --vnet-name $VNET --disable-private-link-service-network-policies true

# Create the cluster (Minimum 3 worker nodes must be used)
$ az aro create --resource-group $RESOURCEGROUP --name $CLUSTER --vnet $VNET --master-subnet $MASTSUB --worker-count 3 --worker-subnet $WORKSUB
```

After executing the `az aro create` command, it normally takes about 35 minutes
to create a cluster.

Notice that creating an ARO cluster requires the `User Access Administrator`
permissions. The following error is printed when your account does not have
them:
```bash
$ az aro create --resource-group $RESOURCEGROUP --name $CLUSTER --vnet $VNET --master-subnet $MASTSUB --worker-count 3 --worker-subnet $WORKSUB
# The client 'myemail@domain.com' with object id '<my-user-object-id>' does not have authorization to perform action 'Microsoft.Authorization/roleAssignments/write' over scope '/subscriptions/<mySubscription>/resourceGroups/<myResourceName>/providers/Microsoft.Network/virtualNetworks/<myVNET>/providers/Microsoft.Authorization/roleAssignments/a1b2c3d4-eeee-5555-ffff-6g7h8i9k0000' or the scope is invalid. If access was recently granted, please refresh your credentials
```

If we need to delete our cluster, it is enough to execute:
```bash
$ az group delete --name $RESOURCEGROUP
```

Take into account that it will remove the entire resource group and all
resources inside it.

Further details about creating an ARO cluster can be found in the [Azure Red Hat
OpenShift
documentation](https://docs.microsoft.com/en-us/azure/openshift/tutorial-create-cluster).

### Connect to the cluster

Fist of all, to be able to connect to our cluster, we need the following
information:

```bash
# API Server URL
$ az aro show --subscription $SUBSCRIPTION -g $RESOURCEGROUP -n $CLUSTER --query apiserverProfile.url
https://api.server.example.io:1234

# Credentials
$ az aro list-credentials --subscription $SUBSCRIPTION -g $RESOURCEGROUP -n $CLUSTER
{
  "kubeadminPassword": "myPassword",
  "kubeadminUsername": "myUsername"
}
```

#### From GitHub actions

The `test-integration` job is already configured to authenticate and set the
kubeconf context to the ARO cluster configured in the GitHub repository. So all
we need to do is to add the following actions secrets:

- `OPENSHIFT_SERVER`: The API server URL: `https://api.server.example.io:1234`.
- `OPENSHIFT_USER`: The `kubeadminUsername` from the JSON output of the
  `list-credentials` command.
- `OPENSHIFT_PASSWORD`: The `kubeadminPassword` from the JSON output of the
  `list-credentials` command.

Further details about connect to an ARO cluster from GitHub actions can be found
in the [Azure Red Hat OpenShift
documentation](https://docs.microsoft.com/en-us/azure/openshift/tutorial-connect-cluster#connect-using-the-openshift-cli)
and the [redhat-actions/oc-login
documentation](https://github.com/redhat-actions/oc-login).

#### From a host

For debugging, it might be necessary to connect to the cluster from a host. We
can do it by using the `oc` tool:

```bash
$ oc login $apiServer -u $kubeadminUsername -p $kubeadminPassword
```

Notice that it configures the kubeconf with a new context.

Please take into account that any change done on this cluster could cause issues
with the integration tests running on GitHub actions at that moment.
