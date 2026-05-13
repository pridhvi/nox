package adapters

import "sort"

var globalRegistry = map[string]Adapter{}

func Register(a Adapter) {
	globalRegistry[a.ID()] = a
}

func Get(id string) (Adapter, bool) {
	a, ok := globalRegistry[id]
	return a, ok
}

func All() []Adapter {
	result := make([]Adapter, 0, len(globalRegistry))
	for _, a := range globalRegistry {
		result = append(result, a)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ID() < result[j].ID()
	})
	return result
}
