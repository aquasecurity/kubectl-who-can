package cmd

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"testing"
)

type APIAccessCheckerMock struct {
	mock.Mock
}

func (m *APIAccessCheckerMock) IsAllowedTo(verb, resource string) (bool, error) {
	args := m.Called(verb, resource)
	return args.Bool(0), args.Error(1)
}

func TestCheckAPIAccess(t *testing.T) {

	t.Run("Should return warnings when any check fails", func(t *testing.T) {
		// given
		checker := new(APIAccessCheckerMock)
		checker.On("IsAllowedTo", "list", "roles").Return(true, nil)
		checker.On("IsAllowedTo", "list", "rolebindings").Return(false, nil)
		checker.On("IsAllowedTo", "list", "clusterroles").Return(true, nil)
		checker.On("IsAllowedTo", "list", "clusterrolebindings").Return(false, nil)

		// when
		warnings, err := checkAPIAccess(checker)

		// then
		require.NoError(t, err)
		require.Equal(t, 2, len(warnings))

		assert.Contains(t, warnings, "The user is not allowed to list rolebindings")
		assert.Contains(t, warnings, "The user is not allowed to list clusterrolebindings")

		checker.AssertExpectations(t)
	})

	t.Run("Should return error when API server is down", func(t *testing.T) {
		// given
		checker := new(APIAccessCheckerMock)
		checker.On("IsAllowedTo", "list", "roles").Return(false, errors.New("api is down"))

		// when
		_, err := checkAPIAccess(checker)

		// then
		require.EqualError(t, err, "api is down")
		checker.AssertExpectations(t)
	})

}
