package saml2aws

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProviderList_Keys(t *testing.T) {

	names := MFAsByProvider.Names()

	require.Len(t, names, 6)

}

func TestProviderList_Mfas(t *testing.T) {

	mfas := MFAsByProvider.Mfas("Ping")

	require.Len(t, mfas, 1)

}
