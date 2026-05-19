package policyseal

import "fmt"

const FolderPoWPurpose = "folder-pow-policy"

type FolderPoWPolicy struct {
	RequiredHashrateTHs      float64
	HashrateTolerancePercent float64
	ProofWindowSeconds       int
	MaxProofAttempts         int
}

func FolderPoWPolicyPayload(tenantID string, folderID string, policy FolderPoWPolicy) []byte {
	return []byte(fmt.Sprintf(
		"archivon:folder-pow-policy:v1\n"+
			"tenant_id=%s\n"+
			"folder_id=%s\n"+
			"required_hashrate_ths=%.6f\n"+
			"hashrate_tolerance_percent=%.2f\n"+
			"proof_window_seconds=%d\n"+
			"max_proof_attempts=%d\n",
		tenantID,
		folderID,
		policy.RequiredHashrateTHs,
		policy.HashrateTolerancePercent,
		policy.ProofWindowSeconds,
		policy.MaxProofAttempts,
	))
}
