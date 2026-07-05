package trustedrouter

import "testing"

func TestModelsPath(t *testing.T) {
	open := true
	closed := false
	cases := []struct {
		name string
		opts *ModelListOptions
		want string
	}{
		{"nil", nil, "/models"},
		{"empty", &ModelListOptions{}, "/models"},
		{"open", &ModelListOptions{OpenWeights: &open}, "/models?open_weights=true"},
		{"closed", &ModelListOptions{OpenWeights: &closed}, "/models?open_weights=false"},
		{"all", &ModelListOptions{OpenWeights: &open, ProviderJurisdiction: "us", ProviderRegion: "eu"}, "/models?open_weights=true&provider%5Bjurisdiction%5D=us&provider%5Bregion%5D=eu"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := modelsPath(tc.opts); got != tc.want {
				t.Fatalf("modelsPath() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestModelExtraCapture(t *testing.T) {
	var list ModelList
	data := []byte(`{"data":[{"id":"m","trustedrouter":{"open_weights":true,"new_flag":"x"},"new_model_field":1}],"next":"cursor"}`)
	if err := list.UnmarshalJSON(data); err != nil {
		t.Fatal(err)
	}
	if list.Extra["next"] != "cursor" {
		t.Fatalf("list extra = %#v", list.Extra)
	}
	model := list.ByID("m")
	if model == nil || !model.OpenWeights() {
		t.Fatalf("model = %#v", model)
	}
	if model.Extra["new_model_field"] == nil || model.TrustedRouter.Extra["new_flag"] != "x" {
		t.Fatalf("extra not captured: model=%#v tr=%#v", model.Extra, model.TrustedRouter.Extra)
	}
}
