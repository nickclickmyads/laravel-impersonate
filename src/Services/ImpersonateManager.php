<?php

namespace Lab404\Impersonate\Services;

use Exception;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Foundation\Application;
use Lab404\Impersonate\Events\LeaveImpersonation;
use Lab404\Impersonate\Events\TakeImpersonation;
use Lab404\Impersonate\Exceptions\InvalidUserProvider;
use Lab404\Impersonate\Exceptions\MissingUserProvider;

class ImpersonateManager
{
    const REMEMBER_PREFIX = 'remember_web';

    /** @var Application $app */
    private $app;

    public function __construct(Application $app)
    {
        $this->app = $app;
    }

    /**
     * @param int $id
     * @return \Illuminate\Contracts\Auth\Authenticatable
     * @throws MissingUserProvider
     * @throws InvalidUserProvider
     * @throws ModelNotFoundException
     */
    public function findUserById($id, $guardName = null)
    {
        if (empty($guardName)) {
            $guardName = $this->app['config']->get('auth.default.guard', 'web');
        }

        $providerName = $this->app['config']->get("auth.guards.$guardName.provider");

        if (empty($providerName)) {
            throw new MissingUserProvider($guardName);
        }

        try {
            /** @var UserProvider $userProvider */
            $userProvider = $this->app['auth']->createUserProvider($providerName);
        } catch (\InvalidArgumentException $e) {
            throw new InvalidUserProvider($guardName);
        }

        if (!($modelInstance = $userProvider->retrieveById($id))) {
            $model = $this->app['config']->get("auth.providers.$providerName.model");

            throw (new ModelNotFoundException())->setModel(
                $model,
                $id
            );
        }

        return $modelInstance;
    }

    public function isImpersonating(): bool
    {
        return !empty($this->getImpersonatorId());
    }

    /**
     * @return  int|null
     */
    public function getImpersonatorId()
    {
        return $this->app['auth']->guard($this->getDefaultSessionGuard())->parseToken()->getPayLoad()
            ->get($this->getSessionKey());
    }

    /**
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    public function getImpersonator()
    {
        $id = $this->getImpersonatorId();
        $guard = $this->getImpersonatorGuardName();

        return is_null($id) ? null : $this->findUserById($id, $guard);
    }

    /**
     * @return string|null
     */
    public function getImpersonatorGuardName()
    {
        return $this->app['auth']->guard($this->getDefaultSessionGuard())->parseToken()->getPayLoad()
            ->get($this->getSessionGuard());
    }

    /**
     * @return string|null
     */
    public function getImpersonatorGuardUsingName()
    {
        return $this->app['auth']->guard($this->getDefaultSessionGuard())->parseToken()->getPayLoad()
            ->get($this->getSessionGuardUsing());
    }

    /**
     * @param \Illuminate\Contracts\Auth\Authenticatable $from
     * @param \Illuminate\Contracts\Auth\Authenticatable $to
     * @param string|null                         $guardName
     * @return string
     */
    public function take($from, $to, $guardName = null): string
    {
        $currentGuard = $this->getCurrentAuthGuardName();
        $this->app['auth']->guard($guardName)->customClaims([
            $this->getSessionKey() => $from->getKey(),
            $this->getSessionGuard() => $currentGuard,
            $this->getSessionGuardUsing() => $guardName,
            static::REMEMBER_PREFIX => $this->saveAuthCookies(),
        ]);

        $token = $this->app['auth']->guard($guardName)->login($to);
        $this->app['auth']->guard($guardName)->setToken($token);

        $this->app['events']->dispatch(new TakeImpersonation($from, $to));

        return $token;
    }

    public function leave(): bool
    {
        try {
            $impersonator = $this->getImpersonator();
            $impersonated = $this->app['auth']->guard($this->getImpersonatorGuardUsingName())->user();

            $this->app['auth']->guard($this->getCurrentAuthGuardName())->logout();

            $this->extractAuthCookies();

            $this->clear();

        } catch (Exception $e) {
            unset($e);
            return false;
        }

        $this->app['events']->dispatch(new LeaveImpersonation($impersonator, $impersonated));

        return true;
    }

    public function clear()
    {
        $this->app['auth']->guard($this->getDefaultSessionGuard())->customClaims([
            $this->getSessionKey() => null,
            $this->getSessionGuard() => null,
            $this->getSessionGuardUsing() => null,
            static::REMEMBER_PREFIX => null
        ]);
    }

    public function getSessionKey(): string
    {
        return config('laravel-impersonate.session_key');
    }

    public function getSessionGuard(): string
    {
        return config('laravel-impersonate.session_guard');
    }

    public function getSessionGuardUsing(): string
    {
        return config('laravel-impersonate.session_guard_using');
    }

    public function getDefaultSessionGuard(): string
    {
        return config('laravel-impersonate.default_impersonator_guard');
    }

    public function getLeaveRedirectTo(): string
    {
        try {
            $uri = route(config('laravel-impersonate.leave_redirect_to'));
        } catch (\InvalidArgumentException $e) {
            $uri = config('laravel-impersonate.leave_redirect_to');
        }

        return $uri;
    }

    /**
     * @return array|null
     */
    public function getCurrentAuthGuardName()
    {
        $guards = array_keys(config('auth.guards'));

        foreach ($guards as $guard) {
            if ($this->app['auth']->guard($guard)->check()) {
                return $guard;
            }
        }

        return null;
    }

    protected function saveAuthCookies(): array
    {
        $cookie = $this->findByKeyInArray($this->app['request']->cookies->all(), static::REMEMBER_PREFIX);
        $key = $cookie->keys()->first();
        $val = $cookie->values()->first();

        if (!$key || !$val) {
            return [];
        }

        return [$key, $val];
    }

    protected function extractAuthCookies(): void
    {
        if (!$session = $this->app['auth']->guard($this->getDefaultSessionGuard())->parseToken()->getPayLoad()
            ->get(static::REMEMBER_PREFIX)
        ) {
            return;
        }

        $this->app['cookie']->queue($session[0], $session[1]);
        session()->forget($session);
    }

    /**
     * @param array  $values
     * @param string $search
     * @return \Illuminate\Support\Collection
     */
    protected function findByKeyInArray(array $values, string $search)
    {
        return collect($values ?? session()->all())
            ->filter(function ($val, $key) use ($search) {
                return strpos($key, $search) !== false;
            });
    }
}
