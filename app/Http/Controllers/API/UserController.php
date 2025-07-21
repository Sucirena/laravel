<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Http\Resources\UserResource;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class UserController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index(): JsonResponse{
        $users = User::with(['admin', 'tenagaAhli', 'pasien'])->get();

        if ($users->isEmpty()) {
            return response()->json([
                'status' => 'fail',
                'message' => 'Tidak ada user yang ditemukan.'
            ], 404);
        }

        return response()->json([
            'status' => 'success',
            'data' => UserResource::collection($users)
        ], 200);
    }


    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        //
    }

    /**
     * Display the specified resource.
     */
    public function show(string $id): JsonResponse{
        $user = User::with(['admin', 'tenagaAhli', 'pasien'])->find($id);

        if (!$user) {
            return response()->json([
                'status' => 'fail',
                'message' => 'Pengguna tidak ditemukan.'
            ], 404);
        }

        return (new UserResource($user))
            ->response()
            ->setStatusCode(200);
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, string $id)
    {
        //
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(string $id)
    {
        //
    }
}
