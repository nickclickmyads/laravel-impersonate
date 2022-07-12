<?php

namespace Lab404\Impersonate\Controllers;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Log;
use Lab404\Impersonate\Services\ImpersonateManager;

class ImpersonateController extends Controller
{
    /** @var ImpersonateManager */
    protected $manager;

    /**
     * ImpersonateController constructor.
     */
    public function __construct()
    {
        $this->manager = app()->make(ImpersonateManager::class);
        
        $guard = $this->manager->getDefaultSessionGuard();
        $this->middleware('auth:' . $guard)->only('take');
    }

    /**
     * @param int         $id
     * @param string|null $guardName
     * @return  RedirectResponse
     * @throws  \Exception
     */
    public function take(Request $request, $id, $guardName = null)
    {
        try {
            $guardName = $guardName ?? $this->manager->getDefaultSessionGuard();

            // Cannot impersonate yourself
            if ($id == $request->user()->getAuthIdentifier() && ($this->manager->getCurrentAuthGuardName() == $guardName)) {
                abort(403);
            }

            if (!$request->user()->canImpersonate()) {
                abort(403);
            }

            $userToImpersonate = $this->manager->findUserById($id, $guardName);

            if (!$userToImpersonate->canBeImpersonated()) {
                abort(403);
            }

            return new JsonResource([
                'token' => $this->manager->take($request->user(), $userToImpersonate, $guardName)
            ]);
        } catch (\Throwable $e) {
            Log::info($e->getMessage(), $e->getTrace());
            throw $e;
        }
    }

    /**
     * @return JsonResource
     */
    public function leave()
    {
        if (!$this->manager->isImpersonating()) {
            abort(403);
        }

        $this->manager->leave();

        $leaveRedirect = $this->manager->getLeaveRedirectTo();
        if ($leaveRedirect !== 'back') {
            return new JsonResource(['redirect_url' => $leaveRedirect]);
        }
    }
}
