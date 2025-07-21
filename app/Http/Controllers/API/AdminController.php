<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Http\Resources\AdminResource;
use App\Models\Admin;
use App\Models\User;
use App\Http\Requests\StoreUserRequest;
use App\Http\Requests\UpdateUserRequest;
use Illuminate\Validation\Rule;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\DB;
use Illuminate\Http\JsonResponse;

class AdminController extends BaseController
{
    /**
     * Display a listing of the resource.
     */
    public function index(): JsonResponse
    {
        $admins = Admin::with('user')->get();

        if ($admins->isEmpty()) {
            return $this->sendError('Data admin kosong.', [], 404);
        }
        return $this->sendResponse(AdminResource::collection($admins), 'Data admin berhasil diterima.');
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(StoreUserRequest $request): JsonResponse
    {
        DB::beginTransaction();

        try {
            $user = User::create([
                'role' => $request->role,
                'email' => $request->email,
                'password' => Hash::make($request->password),
                'nama' => $request->nama,
                'jenis_kelamin' => $request->jenis_kelamin,
                'tanggal_lahir' => $request->tanggal_lahir,
                'foto_profil' => $request->foto_profil,
            ]);
            
            $admin = Admin::create([
                'id_user' => $user->id,
                'admin_role' => $request->admin_role,
            ]);
            
            DB::commit();

            $admin->load('user');

            return $this->sendResponse(new AdminResource($admin), 'Data admin berhasil ditambah.');
        } catch (\Exception $e) {
            DB::rollBack();

            return $this->sendError('Data admin gagal ditambah.', [$e->getMessage()], 500);
        }
    }

    /**
     * Display the specified resource.
     */
    public function show(string $id): JsonResponse
    {
        $admin = Admin::with('user')->find($id);

        if (!$admin) {
            return $this->sendError('Data admin tidak ditemukan.', [], 404);
        }

        return $this->sendResponse(new AdminResource($admin), 'Data admin berhasil diterima.');
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(UpdateUserRequest $request, $id): JsonResponse
    {
        DB::beginTransaction();

        try {
            $admin = Admin::with('user')->find($id);
            if (!$admin) {
                return $this->sendError('Data admin tidak ditemukan.', [], 404);
            }
            
            $user = $admin->user;
    
            $request->validate([
                'email' => [
                    'required',
                    'email',
                    Rule::unique('user', 'email')->ignore($user->id),
                ],
            ]);
    
            $user->update([
                'email' => $request->email,
                'password' => $request->filled('password') ? Hash::make($request->password) : $user->password,
                'nama' => $request->nama,
                'jenis_kelamin' => $request->jenis_kelamin,
                'tanggal_lahir' => $request->tanggal_lahir,
                'foto_profil' => $request->foto_profil,
            ]);
    
            $admin->update([
                'admin_role' => $request->admin_role,
            ]);
    
            DB::commit();

            return $this->sendResponse(new AdminResource($admin), 'Data admin berhasil diperbarui.');
        } catch (\Exception $e) {
            DB::rollBack();

            return $this->sendError('Data admin gagal diperbarui.', [$e->getMessage()], 500);
        }
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(string $id): JsonResponse{
        $admin = Admin::with('user')->find($id);

        if (!$admin) {
            return $this->sendError('Data admin tidak ditemukan.', [], 404);
        }

        $user = $admin->user;
        $user->delete();

        return $this->sendResponse(new AdminResource($admin), 'Data admin berhasil dihapus.');
    }
}
