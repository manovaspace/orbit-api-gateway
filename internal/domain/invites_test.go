package domain

import "testing"

func TestNormalizeInviteRequest(t *testing.T) {
	tests := []struct {
		name    string
		in      InviteRequest
		want    InviteRequest
		message string
	}{
		{"email defaults to member", InviteRequest{OrgID: "org-1", Email: " person@example.com "}, InviteRequest{OrgID: "org-1", Email: "person@example.com", Role: RoleMember}, ""},
		{"phone keeps its tier", InviteRequest{OrgID: "org-1", Phone: "+989121234567", Role: "admin"}, InviteRequest{OrgID: "org-1", Phone: "+989121234567", Role: RoleAdmin}, ""},
		{"owner is a valid tier", InviteRequest{OrgID: "org-1", Email: "a@example.com", Role: "owner"}, InviteRequest{OrgID: "org-1", Email: "a@example.com", Role: RoleOwner}, ""},
		{"both email and phone", InviteRequest{OrgID: "org-1", Email: "a@example.com", Phone: "+989121234567"}, InviteRequest{}, "set exactly one of email or phone"},
		{"neither email nor phone", InviteRequest{OrgID: "org-1"}, InviteRequest{}, "set exactly one of email or phone"},
		{"blank email is no email", InviteRequest{OrgID: "org-1", Email: "   "}, InviteRequest{}, "set exactly one of email or phone"},
		{"unknown tier", InviteRequest{OrgID: "org-1", Email: "a@example.com", Role: "superuser"}, InviteRequest{}, "role must be owner, admin or member"},
		{"tier is case sensitive", InviteRequest{OrgID: "org-1", Email: "a@example.com", Role: "Admin"}, InviteRequest{}, "role must be owner, admin or member"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeInviteRequest(tc.in)
			if tc.message != "" {
				failure, ok := AsError(err)
				if !ok || failure.Kind != KindInvalidArgument || failure.Message != tc.message {
					t.Fatalf("err = %v, want invalid argument %q", err, tc.message)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("NormalizeInviteRequest = %+v, %v; want %+v", got, err, tc.want)
			}
		})
	}
}
