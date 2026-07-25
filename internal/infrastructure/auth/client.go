package auth

import (
	authv1 "github.com/manovaspace/orbit-auth/api/auth/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Client struct {
	api  authv1.AuthServiceClient
	conn *grpc.ClientConn
}

func NewClient(addr string, opts ...grpc.DialOption) (*Client, error) {
	base := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	opts = append(base, opts...)
	conn, err := grpc.NewClient(addr, opts...)
	if err != nil {
		return nil, err
	}
	return &Client{api: authv1.NewAuthServiceClient(conn), conn: conn}, nil
}

func (c *Client) API() authv1.AuthServiceClient {
	return c.api
}

func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}
