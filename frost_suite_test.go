package frost_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestFrost(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Frost Suite")
}
