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
	"strings"

	investigation "github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	corev1 "k8s.io/api/core/v1"
	metricsv1beta1 "k8s.io/metrics/pkg/apis/metrics/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Investigation struct{}

func (c *Investigation) Run(r *investigation.Resources) (investigation.InvestigationResult, error) {
	result := investigation.InvestigationResult{}
	// Initialize PagerDuty note writer
	notes := notewriter.New(r.Name, logging.RawLogger)

	//Step: node-exporter consuming high cpu in SDN clusters
	//Step: oc get Network.config.openshift.io cluster -o json | jq '.spec.networkType'
	network := r.Cluster.Network().Type()
	// Initialize k8s client
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
			fmt.Printf("Container Name: %v, Ready: %v, ContainerStatus State: %v",
				containerStatus.Name, containerStatus.Ready, containerStatus.State)

			// Convert ContainerStatus to text
			containerText := fmt.Sprintf("Container Name: %v, Ready: %v, Restart Count: %v, Image: %v, State: %v", containerStatus.Name,
				containerStatus.Ready, containerStatus.RestartCount, containerStatus.Image, containerStatus.State)

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

func (c *Investigation) Name() string {
	return "pruningcronjoberror"
}
func (c *Investigation) Description() string {
	return "Steps through PruningCronjobError SOP"
}

func (c *Investigation) ShouldInvestigateAlert(alert string) bool {
	return strings.Contains(alert, "PruningCronjobErrorSRE")
}

func (c *Investigation) IsExperimental() bool {
	return false
}
