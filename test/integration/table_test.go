package integration

import (
	"fmt"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes"
)

func ProviderSuccessTestTable(t *testing.T, clientset *kubernetes.Clientset, storeTest StoreTest) {
	tests := []runImageAdmissionTestStruct{
		{
			name:          "default-unsigned-sbom-warn",
			image:         "busybox:latest",
			expectedError: "",
			format:        "statement",
			store:         storeTest.Type(),
			bomFlags:      storeTest.BomFlags(t, "bom", ConfigPath),
			valuesConfig:  storeTest.MakeValuesConfig(t, "x509-env", CaPath, devTag),
			bomAssertions: []traitAssertion{
				assertInOutput(fmt.Sprintf("[%s] upload success ref=", storeTest.Type())),
				assertSuccessfulReturnCode,
			},
			admissionAssertions: []traitAssertion{
				assertInOutput("policy-select: policies evaluated successfully"),
				assertInOutput("resource not found, no evidence found"),
				assertNotInOutput("Scribe Admission refused"),
				assertSuccessfulReturnCode,
			},
		},
		{
			name:          "default-signed-sbom",
			image:         "alpine:latest",
			expectedError: "",
			format:        "attest",
			store:         storeTest.Type(),
			bomFlags:      storeTest.BomFlags(t, "bom", ConfigPath),
			valuesConfig:  storeTest.MakeValuesConfig(t, "x509-env", CaPath, devTag),
			bomAssertions: []traitAssertion{
				assertInOutput(fmt.Sprintf("[%s] upload success ref=", storeTest.Type())),
				assertSuccessfulReturnCode,
			},
			admissionAssertions: []traitAssertion{
				assertInOutput("policy-select: policies evaluated successfully"),
				assertInOutput("1/1 evidence origin and signature verified"),
				assertNotInOutput("Scribe Admission refused"),
				assertSuccessfulReturnCode,
			},
		},
		{
			name:          "require-sbom-exists",
			image:         "busybox:latest",
			expectedError: "",
			format:        "statement",
			store:         storeTest.Type(),
			bomFlags:      storeTest.BomFlags(t, "bom", ConfigPath),
			valuesConfig:  storeTest.MakeValuesConfig(t, "x509-env", CaPath, devTag),
			policyConfig: map[string]interface{}{
				"select": map[string]interface{}{
					"gate": "require-sbom-exists",
					"apply": []map[string]interface{}{
						{
							"namespace": "",             // Any
							"glob":      []string{"**"}, // Any
							"filter-by": []string{"target"},
							"policy": map[string]interface{}{
								"name": "require-sbom-exists",
								"rules": []map[string]interface{}{
									{
										"name":  "require-sbom-exists",
										"uses":  "sboms/evidence-exists@v1",
										"level": "error",
									},
								},
							},
						},
					},
				},
			},
			bomAssertions: []traitAssertion{
				assertInOutput(fmt.Sprintf("[%s] upload success ref=", storeTest.Type())),
				assertSuccessfulReturnCode,
			},
			admissionAssertions: []traitAssertion{
				assertInOutput("policy-select: policies evaluated successfully"),
				assertInOutput("resource not found, no evidence found"),
				assertNotInOutput("Scribe Admission refused"),
				assertSuccessfulReturnCode,
			},
		},
		{
			name:          "require-artifact-fresh-signed",
			image:         "alpine:latest",
			expectedError: "",
			format:        "attest",
			store:         storeTest.Type(),
			bomFlags:      storeTest.BomFlags(t, "bom", ConfigPath),
			valuesConfig:  storeTest.MakeValuesConfig(t, "x509-env", CaPath, devTag),
			policyConfig: map[string]interface{}{
				"select": map[string]interface{}{
					"gate": "require-artifact-fresh-signed",
					"apply": []map[string]interface{}{
						{
							"namespace": "",             // Any
							"glob":      []string{"**"}, // Any
							"filter-by": []string{"target"},
							"policy": map[string]interface{}{
								"name": "require-artifact-fresh-signed",
								"rules": []map[string]interface{}{
									{
										"name":  "require-artifact-signed",
										"uses":  "sboms/artifact-signed@v1",
										"level": "error",
									},
									{
										"name":  "require-artifact-fresh",
										"uses":  "images/fresh-image@v1",
										"level": "error",
										"evidence": map[string]interface{}{
											"signed": true,
										},
										"with": map[string]interface{}{
											"max_days": 1000,
										},
									},
								},
							},
						},
					},
				},
			},
			bomAssertions: []traitAssertion{
				assertInOutput(fmt.Sprintf("[%s] upload success ref=", storeTest.Type())),
				assertSuccessfulReturnCode,
			},
			admissionAssertions: []traitAssertion{
				assertInOutput("policy-select: policies evaluated successfully"),
				assertInOutput("resource not found, no evidence found"),
				assertInOutput("image is new enough"),
				assertNotInOutput("Scribe Admission refused"),
				assertNotInOutput("image is too old"),
				assertSuccessfulReturnCode,
			},
		},
	}

	defer DeleteK8sDeployment(t, clientset)
	defer UninstallProvider(t, true)
	defer UninstallGatekeeper(t, true)

	for _, test := range tests {
		startTime := time.Now()

		t.Run(test.name, func(t *testing.T) {
			name := fmt.Sprintf("provider.%s.%s.%s", t.Name(), test.store, test.name)
			productVersion := runNum
			if productVersion == "" {
				productVersion = "local"
			}

			bomFlags := MakeBomFlags(t, test.bomFlags, test.format, test.image, name, productVersion)

			t.Log("###### Testing ", test.name, "######")
			InstallGatekeeper(t)
			InstallProvider(t, test.valuesConfig, test.policyConfig, test.format)

			runImageAdmissionTest(t, test, clientset, bomFlags)

			DeleteK8sDeployment(t, clientset)
			UninstallProvider(t, false)
			UninstallGatekeeper(t, false)
		})
		endTime := time.Now()
		elapsed := endTime.Sub(startTime)
		fmt.Printf("Elapsed: %s\n", elapsed)
	}
}

func ProviderFailTestTable(t *testing.T, clientset *kubernetes.Clientset, storeTest StoreTest) {
	tests := []runImageAdmissionTestStruct{
		{
			name:          "require-artifact-sign",
			image:         "busybox:latest",
			expectedError: "no evidence found",
			format:        "statement",
			store:         storeTest.Type(),
			bomFlags:      storeTest.BomFlags(t, "bom", ConfigPath),
			valuesConfig:  storeTest.MakeValuesConfig(t, "x509-env", CaPath, devTag),
			policyConfig: map[string]interface{}{
				"select": map[string]interface{}{
					"gate": "require-artifact-signed",
					"apply": []map[string]interface{}{
						{
							"namespace": "",             // Any
							"glob":      []string{"**"}, // Any
							"filter-by": []string{"target"},
							"policy": map[string]interface{}{
								"name": "require_signed_sbom",
								"rules": []map[string]interface{}{
									{
										"name":  "require-artifact-signed",
										"uses":  "sboms/artifact-signed@v1",
										"level": "error",
									},
								},
							},
						},
					},
				},
			},
			bomAssertions: []traitAssertion{
				assertInOutput(fmt.Sprintf("[%s] upload success ref=", storeTest.Type())),
				assertSuccessfulReturnCode,
			},
			admissionAssertions: []traitAssertion{
				assertInOutput("resource not found, no evidence found"),
				assertInOutput("Scribe Admission refused"),
				assertSuccessfulReturnCode,
			},
		},
		{
			name:          "require-artifact-fresh-sign",
			image:         "alpine:latest",
			expectedError: "no evidence found",
			format:        "attest",
			store:         storeTest.Type(),
			bomFlags:      storeTest.BomFlags(t, "bom", ConfigPath),
			valuesConfig:  storeTest.MakeValuesConfig(t, "x509-env", CaPath, devTag),
			policyConfig: map[string]interface{}{
				"select": map[string]interface{}{
					"gate": "require-artifact-fresh-signed",
					"apply": []map[string]interface{}{
						{
							"namespace": "",             // Any
							"glob":      []string{"**"}, // Any
							"filter-by": []string{"target"},
							"policy": map[string]interface{}{
								"name": "require_signed_fresh_sbom",
								"rules": []map[string]interface{}{
									{
										"name":  "require-artifact-signed",
										"uses":  "sboms/artifact-signed@v1",
										"level": "error",
									},
									{
										"name":  "require-artifact-fresh",
										"uses":  "images/fresh-image@v1",
										"level": "error",
										"with": map[string]interface{}{
											"max_days": 1,
										},
									},
								},
							},
						},
					},
				},
			},
			bomAssertions: []traitAssertion{
				assertInOutput(fmt.Sprintf("[%s] upload success ref=", storeTest.Type())),
				assertSuccessfulReturnCode,
			},
			admissionAssertions: []traitAssertion{
				assertInOutput("resource not found, no evidence found"),
				assertInOutput("Scribe Admission refused"),
				assertInOutput("image is too old"),
				assertSuccessfulReturnCode,
			},
		},
	}

	defer DeleteK8sDeployment(t, clientset)
	defer UninstallProvider(t, true)
	defer UninstallGatekeeper(t, true)
	InstallGatekeeper(t)

	for _, test := range tests {
		startTime := time.Now()

		t.Run(test.name, func(t *testing.T) {
			name := fmt.Sprintf("provider.%s.%s.%s", t.Name(), test.store, test.name)
			productVersion := runNum
			if productVersion == "" {
				productVersion = "local"
			}

			bomFlags := MakeBomFlags(t, test.bomFlags, test.format, test.image, name, productVersion)

			t.Log("###### Testing ", test.name, "######")
			InstallProvider(t, test.valuesConfig, test.policyConfig, test.format)

			runImageAdmissionTest(t, test, clientset, bomFlags)

			//Give the admission a second to push logs
			time.Sleep(3 * time.Second)

			DeleteK8sDeployment(t, clientset)
			UninstallProvider(t, false)
		})
		endTime := time.Now()
		elapsed := endTime.Sub(startTime)
		fmt.Printf("Elapsed: %s\n", elapsed)
	}

	//Give the admission a second to push logs
	time.Sleep(3 * time.Second)

	UninstallGatekeeper(t, true)

}
