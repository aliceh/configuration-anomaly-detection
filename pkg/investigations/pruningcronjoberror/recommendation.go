/*
machinehealthcheckunterminatedshortcircuitsre defines the investigation logic for the MachineHealthCheckUnterminatedShortCircuitSRE alert
*/
package pruningcronjoberror

import (
	"fmt"
)

// machineRecommendations categorizes each machine's individual investigation summary into a recommended course of action
type investigationRecommendations map[recommendedAction][]investigationResult

func (r investigationRecommendations) addRecommendation(action recommendedAction, object string, notes string) {
	recommendation := investigationResult{
		object: object,
		notes:  notes,
	}
	r[action] = append(r[action], recommendation)
}

type investigationResult struct {
	// name indicates which object was investigated
	object string
	// notes provides a high-level summary of the investigation results
	notes string
}

func (s *investigationResult) String() string {
	msg := fmt.Sprintf("%q: %s", s.object, s.notes)
	return msg
}

// recommendedAction acts as both a key in the investigationRecommendations map, as well as a header for pagerduty notes when summarize()-ing
type recommendedAction string

const (
	// recommendationRetryFailedPruningCronjob indicates that the pruningcronjob should be re-tried
	recommendationRetryFailedPruningCronjob recommendedAction = "retry the pruning cronjob"
	// recommendationInvestigateMachine indicates that the machine(s) in question need to be manually investigated
	recommendationInvestigateMachine recommendedAction = "investigate the following machines"
	// recommendationQuotaServiceLog indicates that the machine(s) in question need to be remediated by the customer, and SRE should notify them
	// of that fact via servicelog
	recommendationQuotaServiceLog recommendedAction = "send a service log regarding quota issues for the following machines"
	// recommendationInvestigateNode indicates that the machine's node object is reporting problems which require human intervention to resolve
	recommendationInvestigateNode recommendedAction = "investigate the following nodes"
)
