//go:build !windows

package scanengine

func platformErrorState(error) State {
	return StateError
}
