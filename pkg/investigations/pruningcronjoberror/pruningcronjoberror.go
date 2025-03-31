// pruningcronjoberror remediates the PruningCronjobErrorSRE alerts
// SOP https://github.com/openshift/ops-sop/blob/master/v4/alerts/PruningCronjobErrorSRE.md

// ocm backplane managedjob create SREP/retry-failed-pruning-cronjob

// Step: Known Issues

// node-exporter consuming high cpu in SDN clusters

// Step: Known Issues

// Seccomp error 524

// Step: Quick Fix

package pruningcronjoberror

import (
	"context"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"

	investigation "github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	corev1 "k8s.io/api/core/v1"
	metricsv1beta1 "k8s.io/metrics/pkg/apis/metrics/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type PCJ struct{}

func (c *PCJ) Run(r *investigation.Resources) (investigation.InvestigationResult, error) {
	result := investigation.InvestigationResult{}
	notes := notewriter.New("PCJ", logging.RawLogger)
	bpError, ok := r.AdditionalResources["error"].(error)
	if !ok {
		return result, fmt.Errorf("Missing required CCAM field 'error'")
	}
	logging.Info("Investigating possible missing cloud credentials...")
	if customerRemovedPermissions := customerRemovedPermissions(bpError.Error()); !customerRemovedPermissions {
		// We aren't able to jumpRole because of an error that is different than
		// a removed support role/policy or removed installer role/policy
		// This would normally be a backplane failure.
		return result, fmt.Errorf("credentials are there, error is different: %w", bpError)
	}

	//Step: node-exporter consuming high cpu in SDN clusters
	//Step: oc get Network.config.openshift.io cluster -o json | jq '.spec.networkType'
	network := r.Cluster.Network().Type()

	k8scli, err := k8sclient.New(r.Cluster.ID(), r.OcmClient, r.Name)
	if err != nil {
		return result, fmt.Errorf("unable to initialize k8s cli: %w", err)
	}
	defer func() {
		deferErr := k8sclient.Cleanup(r.Cluster.ID(), r.OcmClient, r.Name)
		if deferErr != nil {
			logging.Error(deferErr)
			err = errors.Join(err, deferErr)
		}
	}()

	//"OpenshiftSDN" means it is a SDN cluster and may impact by this issue.
	//Check if node-exporter pods are taking up high CPU
	//oc adm top pod -n openshift-monitoring | grep node-exporter
	if network == "OpenshiftSDN" {
		// Fetch pod metrics in the "openshift-monitoring" namespace
		podMetricsList := &metricsv1beta1.PodMetricsList{}
		err = k8scli.List(context.TODO(), podMetricsList, client.HasLabels{"app.kubernetes.io/name=node-exporter"}, client.InNamespace("openshift-monitoring"))
		if err != nil {
			notes.AppendWarning("Error fetching pod metrics for node-exporters: %v\n", err)
		}

		// Check CPU consumption on node-exporter pods
		//Usually a node-exporter pod consumes less than 20m CPU. If you see a node-exporter pod is consuming higher than 100m, it likely hits this issue.

		for _, podMetrics := range podMetricsList.Items {
			fmt.Println("podMetric: %#v", podMetrics)
			//if podMetrics.("CPU") > 100 {
			//	notes.AppendWarning("Find the corresponding node which the node-exporter pod has high CPU consumption, follow the SOP to reboot or replace the node https://github.com/openshift/ops-sop/blob/master/v4/howto/node.md ")
			//}

		}

	}

	//Step: Known issue Seccomp error 524
	//https://github.com/openshift/ops-sop/blob/master/v4/alerts/PruningCronjobErrorSRE.md#seccomp-error-524
	//oc describe pod ${POD} -n openshift-sre-pruning
	prunerPods := &corev1.PodList{}
	err = k8scli.List(context.TODO(), prunerPods, client.InNamespace("openshift-sre-pruning"))

	fmt.Println("Hello World")

	// Iterate through the pods and print their .status.containerStatuses
	for _, pod := range prunerPods.Items {
		fmt.Printf("Pod Name: %s\n", pod.Name)
		for _, containerStatus := range pod.Status.ContainerStatuses {
			fmt.Printf("  Container Name: %s, Ready: %t, Restart Count: %d\n",
				containerStatus.Name, containerStatus.Ready, containerStatus.RestartCount)

			// Convert ContainerStatus to text
			containerText := fmt.Sprintf(
				"Container Name: %s, Ready: %t, Restart Count: %d, Image: %s",
				containerStatus.Name,
				containerStatus.Ready,
				containerStatus.RestartCount,
				containerStatus.Image,
			)

			if strings.Contains(containerText, "seccomp filter: errno 524") {
				fmt.Println("Text contains the seccomp filter: errno 524")
			} else {
				fmt.Println("Text does not contain the seccomp filter: errno 524")
			}
		}
	}

	if err != nil {
		notes.AppendWarning("Error listing pods in openshift-sre-pruning namespace: %v\n", err)
	}

	// want to look at the status condition when it is ContainerCreateFailed
	//.status.containerStatuses

	notes.AppendSuccess("This is a test")

	return result, nil
}

func (c *PCJ) Name() string {
	return "Cluster Credentials Are Missing (PCJ)"
}
func (c *PCJ) Description() string {
	return "Steps through PruningCronjobError SOP"
}

func (c *PCJ) ShouldInvestigateAlert(alert string) bool {
	return false
}

func (c *PCJ) IsExperimental() bool {
	return false
}

var userCausedErrors = []string{
	// OCM can't access the installer role to determine the trust relationship on the support role,
	// therefore we don't know if it's the isolated access flow or the old flow, e.g.:
	// status is 404, identifier is '404', code is 'CLUSTERS-MGMT-404' and operation identifier is '<id>': Failed to find trusted relationship to support role 'RH-Technical-Support-Access'
	// See https://issues.redhat.com/browse/OSD-24270
	".*Failed to find trusted relationship to support role 'RH-Technical-Support-Access'.*",

	// OCM role can't access the installer role, this happens when customer deletes/modifies the trust policy of the installer role, e.g.:
	// status is 400, identifier is '400', code is 'CLUSTERS-MGMT-400' and operation identifier is '<id>': Please make sure IAM role 'arn:aws:iam::<ocm_role_aws_id>:role/ManagedOpenShift-Installer-Role' exists, and add 'arn:aws:iam::<id>:role/RH-Managed-OpenShift-Installer' to the trust policy on IAM role 'arn:aws:iam::<id>:role/ManagedOpenShift-Installer-Role': Failed to assume role: User: arn:aws:sts::<id>:assumed-role/RH-Managed-OpenShift-Installer/OCM is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::<customer_aws_id>:role/ManagedOpenShift-Installer-Role
	".*RH-Managed-OpenShift-Installer/OCM is not authorized to perform: sts:AssumeRole on resource.*",

	// Customer deleted the support role, e.g.:
	// status is 404, identifier is '404', code is 'CLUSTERS-MGMT-404' and operation identifier is '<id>': Support role, used with cluster '<cluster_id>', does not exist in the customer's AWS account
	".*Support role, used with cluster '[a-z0-9]{32}', does not exist in the customer's AWS account.*",

	// This error is the response from backplane calls when:
	// trust policy of ManagedOpenShift-Support-Role is changed
	".*could not assume support role in customer's account: AccessDenied:.*",

	// Customer removed the `GetRole` permission from the Installer role.
	// Failed to get role: User: arn:aws:sts::<id>:assumed-role/ManagedOpenShift-Installer-Role/OCM is not authorized to perform: iam:GetRole on resource: role ManagedOpenShift-Support-Role because no identity-based policy allows the iam:GetRole action
	".*is not authorized to perform: iam:GetRole on resource: role.*",
}

func customerRemovedPermissions(backplaneError string) bool {
	for _, str := range userCausedErrors {
		re, err := regexp.Compile(str)
		if err != nil {
			// This should never happen on production as we would run into it during unit tests
			log.Fatal("failed to regexp.Compile string in `userCausedErrors`")
		}

		if re.MatchString(backplaneError) {
			return true
		}
	}

	return false
}
