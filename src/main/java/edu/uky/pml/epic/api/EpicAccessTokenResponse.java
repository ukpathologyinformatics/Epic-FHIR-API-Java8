package edu.uky.pml.epic.api;

public class EpicAccessTokenResponse {
    public String access_token;
    public String token_type;
    public int expires_in;
    public String scope;

    public String error;
    public String error_description;
}
