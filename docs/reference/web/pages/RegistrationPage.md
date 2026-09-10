# Page: `RegistrationPage`

Route: `/register` (public). The page reads an invitation token from the URL query string, validates it with `GET /auth/register/validate`, collects a 12-character minimum password and profile fields, then submits `POST /auth/register`. On success it stores `noc_token` and `noc_user` in `sessionStorage` and navigates to the first allowed page.

Invalid, missing, or expired invitations remain on the page with an error. Password mismatch and minimum length are validated before the request. Theme and default shift are profile choices, not authorization controls.
