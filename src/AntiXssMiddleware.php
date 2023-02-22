<?php

namespace DMT\Http\AntiXss\Middleware;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use RuntimeException;
use voku\helper\AntiXSS;

/**
 * Class AntiXssMiddleware
 */
class AntiXssMiddleware implements MiddlewareInterface
{
    protected ResponseFactoryInterface $responseFactory;
    protected array $methods;
    private AntiXSS $antiXss;

    public function __construct(ResponseFactoryInterface $responseFactory, array $methods = ['get', 'post', 'put', 'patch'])
    {
        $this->antiXss = new AntiXSS();
        $this->responseFactory = $responseFactory;
        $this->methods = array_map('strtoupper', $methods);
    }

    /**
     * @param ServerRequestInterface $request
     * @param RequestHandlerInterface $handler
     * @return ResponseInterface
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        try {
            if (in_array(strtoupper($request->getMethod()), $this->methods)) {
                $this->xssCheckQueryParams($request);
                $this->xssCheckBody($request);
            }
        } catch (RuntimeException $exception) {
            return $this->responseFactory->createResponse(400, '400 Bad Request');
        }

        return $handler->handle($request);
    }

    /**
     * @param ServerRequestInterface $request
     * @return void
     * @throws RuntimeException
     */
    protected function xssCheckBody(ServerRequestInterface $request): void
    {
        $parsedBody = $request->getParsedBody();

        if (is_null($parsedBody)) {
            return;
        }

        if (is_string($parsedBody) || is_array($parsedBody)) {
            $this->antiXss->xss_clean($parsedBody);
        }

        if (is_object($parsedBody)) {
            $this->antiXss->xss_clean(get_object_vars($parsedBody));
        }

        if ($this->antiXss->isXssFound()) {
            throw new RuntimeException('Cross site scripting detected');
        }
    }

    /**
     * @param ServerRequestInterface $request
     * @return void
     * @throws RuntimeException
     */
    public function xssCheckQueryParams(ServerRequestInterface $request): void
    {
        $params = $request->getQueryParams();

        if (!$params) {
            return;
        }

        $this->antiXss->xss_clean($params);

        if ($this->antiXss->isXssFound()) {
            throw new RuntimeException('Cross site scripting detected');
        }
    }
}
