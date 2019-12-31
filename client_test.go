package tesla

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func TestClientSpec(t *testing.T) {
	ts := serveHTTP(t)
	defer ts.Close()
	previousAuthURL := AuthURL
	previousURL := BaseURL
	AuthURL = ts.URL + "/oauth/token"
	BaseURL = ts.URL + "/api/1"

	auth := &Auth{
		GrantType:    "password",
		ClientID:     "abc123",
		ClientSecret: "def456",
		Email:        "elon@tesla.com",
		Password:     "go",
	}
	client, err := NewClient(auth)

	Convey("Should set the HTTP headers", t, func() {
		req, _ := http.NewRequest("GET", "http://foo.com", nil)
		client.setHeaders(req)
		So(req.Header.Get("Authorization"), ShouldEqual, "Bearer ghi789")
		So(req.Header.Get("Accept"), ShouldEqual, "application/json")
		So(req.Header.Get("Content-Type"), ShouldEqual, "application/json")
	})
	Convey("Should login and get an access token", t, func() {
		So(err, ShouldBeNil)
		So(client.Token.AccessToken, ShouldEqual, "ghi789")
	})

	AuthURL = previousAuthURL
	BaseURL = previousURL
}

func TestTokenExpiredSpec(t *testing.T) {
	// Expired token
	expiredToken := &Token{
		AccessToken: "foo",
		TokenType:   "bar",
		ExpiresIn:   1,
		Expires:     0,
	}

	validToken := &Token{
		AccessToken: "foo",
		TokenType:   "bar",
		ExpiresIn:   1,
		Expires:     9999999999999,
	}

	client := &Client{
		Token: expiredToken,
	}

	Convey("Should have an expired token", t, func() {
		So(client.Token.IsExpired(), ShouldBeTrue)
	})

	client.Token = validToken
	Convey("Should have a valid token", t, func() {
		So(client.Token.IsExpired(), ShouldBeFalse)
	})

}

func TestClientWithTokenSpec(t *testing.T) {
	ts := serveHTTP(t)
	defer ts.Close()
	previousAuthURL := AuthURL
	previousURL := BaseURL
	AuthURL = ts.URL + "/oauth/token"
	BaseURL = ts.URL + "/api/1"

	auth := &Auth{
		GrantType:    "password",
		ClientID:     "abc123",
		ClientSecret: "def456",
		Email:        "elon@tesla.com",
		Password:     "go",
	}

	validToken := &Token{
		AccessToken: "foo",
		TokenType:   "bar",
		ExpiresIn:   4000,
		Expires:     99999999999,
	}

	client, err := NewClientWithToken(auth, validToken)

	Convey("Should login with a valid access token", t, func() {
		So(err, ShouldBeNil)
		So(client.Token.AccessToken, ShouldEqual, "foo")
	})

	AuthURL = previousAuthURL
	BaseURL = previousURL
}

type AuthBody struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Email        string `json:"email"`
	Password     string `json:"password"`
	RefreshToken string `json:"refresh_token"`
	URL          string
	StreamingURL string
}

func serveHTTP(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := ioutil.ReadAll(req.Body)
		defer req.Body.Close()
		switch req.URL.String() {
		case "/oauth/token":
			checkHeaders(t, req)
			auth := &AuthBody{}
			json.Unmarshal(body, auth)
			switch auth.GrantType {
			case "password":
				// if the request is a password do this
				Convey("Request body should be set correctly", t, func() {
					So(auth.ClientID, ShouldEqual, "abc123")
					So(auth.ClientSecret, ShouldEqual, "def456")
					So(auth.Email, ShouldEqual, "elon@tesla.com")
					So(auth.Password, ShouldEqual, "go")
					So(auth.URL, ShouldEqual, BaseURL)
					So(auth.StreamingURL, ShouldEqual, StreamingURL)
				})
			case "refresh_token":
				Convey("Request body should be set correctly", t, func() {
					So(auth.ClientID, ShouldEqual, "abc123")
					So(auth.ClientSecret, ShouldEqual, "def456")
					So(auth.RefreshToken, ShouldEqual, "xyz312")
					So(auth.GrantType, ShouldEqual, "refresh_token")
				})
			}
			w.WriteHeader(200)

			exp := strconv.FormatInt(time.Now().AddDate(0, 0, 1).Unix()-time.Now().Unix(), 10)

			w.Write([]byte("{\"access_token\": \"ghi789\", \"refresh_token\": \"xyz312\", \"token_type\": \"access_token\", \"expires\":" + exp + "}"))
		case "/api/1/vehicles":
			checkHeaders(t, req)
			w.WriteHeader(200)
			w.Write([]byte(VehiclesJSON))
		case "/api/1/vehicles/1234/mobile_enabled":
			checkHeaders(t, req)
			w.WriteHeader(200)
			w.Write([]byte(TrueJSON))
		case "/api/1/vehicles/1234/data_request/charge_state":
			checkHeaders(t, req)
			w.WriteHeader(200)
			w.Write([]byte(ChargeStateJSON))
		case "/api/1/vehicles/1234/data_request/climate_state":
			w.WriteHeader(200)
			w.Write([]byte(ClimateStateJSON))
		case "/api/1/vehicles/1234/data_request/drive_state":
			checkHeaders(t, req)
			w.WriteHeader(200)
			w.Write([]byte(DriveStateJSON))
		case "/api/1/vehicles/1234/data_request/gui_settings":
			checkHeaders(t, req)
			w.WriteHeader(200)
			w.Write([]byte(GuiSettingsJSON))
		case "/api/1/vehicles/1234/data_request/vehicle_state":
			checkHeaders(t, req)
			w.WriteHeader(200)
			w.Write([]byte(VehicleStateJSON))
		case "/api/1/vehicles/1234/wake_up":
			checkHeaders(t, req)
			w.WriteHeader(200)
			w.Write([]byte(WakeupResponseJSON))
		case "/api/1/vehicles/1234/command/set_charge_limit":
			w.WriteHeader(200)
			Convey("Should receive a set charge limit request", t, func() {
				So(string(body), ShouldEqual, `{"percent": 50}`)
			})
		case "/api/1/vehicles/1234/command/charge_standard":
			checkHeaders(t, req)
			w.WriteHeader(200)
			w.Write([]byte(ChargeAlreadySetJSON))
		case "/api/1/vehicles/1234/command/charge_start":
			checkHeaders(t, req)
			w.WriteHeader(200)
			w.Write([]byte(ChargedJSON))
		case "/api/1/vehicles/1234/command/charge_stop",
			"/api/1/vehicles/1234/command/charge_max_range",
			"/api/1/vehicles/1234/command/charge_port_door_open",
			"/api/1/vehicles/1234/command/flash_lights",
			"/api/1/vehicles/1234/command/honk_horn",
			"/api/1/vehicles/1234/command/auto_conditioning_start",
			"/api/1/vehicles/1234/command/auto_conditioning_stop",
			"/api/1/vehicles/1234/command/door_unlock",
			"/api/1/vehicles/1234/command/door_lock",
			"/api/1/vehicles/1234/command/reset_valet_pin",
			"/api/1/vehicles/1234/command/set_temps?driver_temp=72&passenger_temp=72",
			"/api/1/vehicles/1234/command/remote_start_drive?password=foo":
			checkHeaders(t, req)
			w.WriteHeader(200)
			w.Write([]byte(CommandResponseJSON))
		case "/stream/123/?values=speed,odometer,soc,elevation,est_heading,est_lat,est_lng,power,shift_state,range,est_range,heading":
			w.WriteHeader(200)
			events := StreamEventString + "\n" +
				StreamEventString + "\n" +
				BadStreamEventString + "\n"
			b := bytes.NewBufferString(events)
			b.WriteTo(w)
		case "/api/1/vehicles/1234/command/autopark_request":
			w.WriteHeader(200)
			Convey("Auto park request should have appropriate body", t, func() {
				autoParkRequest := &AutoParkRequest{}
				err := json.Unmarshal(body, autoParkRequest)
				So(err, ShouldBeNil)
				So(autoParkRequest.Action, shouldBeValidAutoparkCommand)
				So(autoParkRequest.VehicleID, ShouldEqual, 456)
				So(autoParkRequest.Lat, ShouldEqual, 35.1)
				So(autoParkRequest.Lon, ShouldEqual, 20.2)
			})
		case "/api/1/vehicles/1234/command/trigger_homelink":
			w.WriteHeader(200)
			Convey("Auto park request should have appropriate body", t, func() {
				autoParkRequest := &AutoParkRequest{}
				err := json.Unmarshal(body, autoParkRequest)
				So(err, ShouldBeNil)
				So(autoParkRequest.Lat, ShouldEqual, 35.1)
				So(autoParkRequest.Lon, ShouldEqual, 20.2)
			})
		case "/api/1/vehicles/1234/command/sun_roof_control":
			w.WriteHeader(200)
			Convey("Should set the Pano roof appropriately", t, func() {
				passed := false
				strBody := string(body)
				if strBody == `{"state": "vent", "percent":0}` {
					passed = true
				}
				if strBody == `{"state": "open", "percent":0}` {
					passed = true
				}
				if strBody == `{"state": "move", "percent":50}` {
					passed = true
				}
				if strBody == `{"state": "close", "percent":0}` {
					passed = true
				}
				So(passed, ShouldBeTrue)

			})
		}
	}))
}

func checkHeaders(t *testing.T, req *http.Request) {
	Convey("HTTP headers should be present", t, func() {
		So(req.Header["Accept"][0], ShouldEqual, "application/json")
		So(req.Header["Content-Type"][0], ShouldEqual, "application/json")
	})
}

func shouldBeValidAutoparkCommand(actual interface{}, expected ...interface{}) string {
	if actual == "start_forward" || actual == "start_reverse" || actual == "abort" {
		return ""
	} else {
		return "The Autopark command should pass start_forward, start_reverse or abort"
	}
}
