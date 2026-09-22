//revive:disable:package-comments
package cli

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	"uuid"

	"connectrpc.com/connect/v2"
	"github.com/caarlos0/env/v11"

	grpcdclient "github.com/grpcd/connect-client/client"
	"github.com/grpcd/connect-client/discover"
	connectclient "github.com/pbrpc/connect-client"
	connectserver "github.com/pbrpc/connect-server"
	"github.com/pbrpc/connect-service/diagnostics"
	"github.com/pbrpc/connect-service/health"
	service_lib "github.com/pbrpc/connect-service/service"
	transport "github.com/pbrpc/http-transport"
	"github.com/pbrpc/lifecycle"
	pbrpcotel "github.com/pbrpc/otel"
	svc "github.com/pbrpc/service"

	"github.com/authaas/identity-data-bindings-connect-go/identity/data/dataconnect"
	"github.com/authaas/token-issuer-service-bindings-connect-go/token/issuer/issuerconnect"
	"github.com/authaas/token-issuer-service-connect-go/internal/service"
	"github.com/authaas/token-issuer-service-connect-go/internal/signing"
)

// cleanupTimeout bounds stopping the server and flushing telemetry, together
const cleanupTimeout = 5 * time.Second

// Run serves until a signal arrives or serving fails, and answers with the
// process exit code.
func Run() int {
	ctx := context.Background()

	serveCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	svcCfg := svc.Configuration{Name: "token-issuer"}
	if err := env.Parse(&svcCfg); err != nil {
		slog.Default().Error("Failed to read configuration", slog.Any("error", err))
		return 1
	}

	stack := lifecycle.Stack{}

	log, flush, err := pbrpcotel.Init(ctx, svcCfg.Name, svcCfg.Version, uuid.New().String())
	if err != nil {
		slog.Default().Error("Failed to initialize telemetry", slog.Any("error", err))
		return 1
	}
	stack.Push(lifecycle.Logged(log, "telemetry", flush))

	host, err := connectserver.FromEnv(log)
	if err != nil {
		log.Error("Failed to create connect server", slog.Any("error", err))
		return 1
	}
	stack.Push(lifecycle.Logged(log, "server", host.HTTPHost.Server.Shutdown))

	defer lifecycle.HandleGracefulShutdown(ctx, log, &stack, cleanupTimeout)

	// Nothing is minted without the key, so a signing configuration that does
	// not parse is a startup failure.
	signingCfg, err := env.ParseAs[signing.Configuration]()
	if err != nil {
		log.Error("Could not read signing configuration", slog.Any("error", err))
		return 1
	}

	// Nothing is issued without the data service, which is discovered, so the
	// grpcd address is required.
	configured, err := env.ParseAsWithOptions[grpcdclient.Configuration](
		env.Options{RequiredIfNoDef: true})
	if err != nil {
		log.Error("Could not read configuration", slog.Any("error", err))
		return 1
	}

	base, err := transport.From(nil)
	if err != nil {
		log.Error("Could not build transport", slog.Any("error", err))
		return 1
	}
	conn := grpcdclient.Connect(configured.GRPCDAddress, base)

	// One discovery per process, over the instrumented transport. The data
	// service is reached through the holding transport: each procedure this
	// calls is resolved to a replica, held, and watched, and every call to it
	// goes to the replica held for it.
	discovery := discover.New(serveCtx, log, conn, pbrpcotel.NewTransport(base))
	httpClient := &http.Client{Transport: discovery.Held()}

	checks := diagnostics.Checks{grpcdclient.CheckName: grpcdclient.Check(conn)}

	for _, procedure := range []string{
		dataconnect.ServiceGetGrantHashProcedure,
		dataconnect.ServiceClearGrantProcedure,
	} {
		var upstream *discover.Upstream
		upstream, err = discovery.Upstream(discover.URL(procedure))
		if err != nil {
			log.Error("Failed to name the data upstream",
				slog.String("procedure", procedure), slog.Any("error", err))
			return 1
		}

		checks[procedure] = diagnostics.NewUpstreamCheck(httpClient, upstream)

		// Held for the life of the process: resolved now, and again whenever
		// the replica held is dropped, with or without a request arriving to
		// ask.
		go upstream.Hold(serveCtx)
	}

	dataClient := dataconnect.NewServiceClient(connectclient.New(httpClient, discover.BaseURL, nil))

	server := service.New(dataClient, signingCfg)

	methodList, err := service_lib.Register(
		host.Server,
		host.HTTPHost.Mux,
		health.NewServer(),
		checks,
		func(rpc *connect.Server) {
			issuerconnect.RegisterServiceHandler(rpc, server)
		},
	)
	if err != nil {
		log.Error("Failed to register services", slog.Any("error", err))
		return 1
	}

	lis, err := net.Listen("tcp", svcCfg.Address)
	if err != nil {
		log.Error("Failed to create listener", slog.Any("error", err))
		return 1
	}

	log = log.With(slog.String("address", lis.Addr().String()))

	// Register holds the stream open; its ending is what removes the rows, so
	// there is no deregistration to wait for here.
	go grpcdclient.New(log, svcCfg.Name, lis.Addr(), methodList, conn).Register(serveCtx)

	serveErr := make(chan error, 1)
	go func() { serveErr <- host.Serve(lis) }()

	log.Info("Connect server listening")

	select {
	case err := <-serveErr:
		if err != nil {
			log.Error("Failed to serve", slog.Any("error", err))
			return 1
		}
	case <-serveCtx.Done():
	}

	return 0
}
