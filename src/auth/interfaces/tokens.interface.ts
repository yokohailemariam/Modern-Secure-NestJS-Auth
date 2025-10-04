export interface Tokens {
  accessToken: string;
  refreshToken: string;
}

export interface TokenPayloadResponse {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}
