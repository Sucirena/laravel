<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Http\Requests\StoreUserRequest;
use App\Http\Requests\UpdateUserRequest;
use App\Models\Pasien;
use App\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Storage;
use Illuminate\Validation\Rule;
use Illuminate\Support\Facades\Auth;

class PasienController extends Controller
{
    public function updateProfile(UpdateUserRequest $request)
    {
        $pasien = Pasien::with('user')->where('id_user', Auth::user()->id)->firstOrFail();
        $user = $pasien->user;
    
        DB::beginTransaction();
    
        try {
            $user->update([
                'role' => $request->role,
                'nama' => $request->nama,
                'jenis_kelamin' => $request->jenis_kelamin,
                'tanggal_lahir' => $request->tanggal_lahir,
            ]);
    
            if ($request->hasFile('foto_profil')) {
                if ($user->foto_profil) {
                    Storage::disk('public')->delete($user->foto_profil);
                }
    
                $path = $request->file('foto_profil')->store('image/foto_profil', 'public');
                $user->update(['foto_profil' => $path]);
            }
    
            $pasien->update([
                'deskripsi_diri' => $request->deskripsi_diri,
            ]);
    
            DB::commit();
    
            return redirect()->back()->with('success', 'Profil berhasil diperbarui.');
        } catch (\Exception $e) {
            DB::rollBack();
            return redirect()->back()->with('error', 'Terjadi kesalahan saat memperbarui profil.');
        }
    }
    
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        $pasiens = Pasien::with('user')->paginate(10);
        return view('Admin/data_pasien', [
            "title" => "Data Pasien",
            "pasiens" => $pasiens
        ]);
    }

    /**
     * Show the form for creating a new resource.
     */
    public function create()
    {
        return view('Admin/Form/tambah_data_pasien', [
            "title" => "Tambah Data Pasien"
        ]);
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(StoreUserRequest $request)
    {
        DB::beginTransaction();

        try {
            if ($request->hasFile('foto_profil')) {
                $foto_profil = $request->file('foto_profil')->store('image/foto_profil', 'public');
            }

            $user = User::create([
                'role' => $request->role,
                'email' => $request->email,
                'password' => Hash::make($request->password),
                'nama' => $request->nama,
                'jenis_kelamin' => $request->jenis_kelamin,
                'tanggal_lahir' => $request->tanggal_lahir,
                'foto_profil' => $foto_profil ?? null,
            ]);

            Pasien::create([
                'id_user' => $user->id,
                'deskripsi_diri' => $request->deskripsi_diri,
            ]);

            DB::commit();
            $totalPasien = Pasien::count();
            $perPage = 10;
            $lastPage = ceil($totalPasien / $perPage);

            return redirect()->route('user-pasien.index', ['page' => $lastPage])
                            ->with('success', 'Data pasien berhasil ditambahkan!');

        } catch (\Exception $e) {
            DB::rollback();
            return redirect()->back()->with('error', 'Data pasien gagal ditambahkan! Pesan error: ' . $e->getMessage());
        }
    }

    /**
     * Display the specified resource.
     */
    public function show(string $id)
    {
        $pasien = Pasien::with('user')->findOrFail($id);
        return view('Admin/Template/data_pasien', [
            "title" => "Data Pasien",
            "pasien" => $pasien
        ]);
    }

    /**
     * Show the form for editing the specified resource.
     */
    public function edit(string $id)
    {
        $pasien = Pasien::with('user')->findOrFail($id);
        return view('Admin/Form/edit_data_pasien', [
            "title" => "Edit Data Pasien",
            "pasien" => $pasien
        ]);
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(UpdateUserRequest $request, $id)
    {
        DB::beginTransaction();

        try {
            $pasien = Pasien::with('user')->findOrFail($id);
            $user = $pasien->user;

            $request->validate([
                'email' => [
                    'required',
                    'email',
                    Rule::unique('user', 'email')->ignore($user->id),
                ],
            ]);

            if ($request->hasFile('foto_profil')) {
                if ($user->foto_profil) {
                    Storage::disk('public')->delete($user->foto_profil);
                }
                $foto_profil = $request->file('foto_profil')->store('image/foto_profil', 'public');
                $user->foto_profil = $foto_profil;
            }

            $user->update([
                'email' => $request->email,
                'password' => $request->filled('password') ? Hash::make($request->password) : $user->password,
                'nama' => $request->nama,
                'jenis_kelamin' => $request->jenis_kelamin,
                'tanggal_lahir' => $request->tanggal_lahir
            ]);

            $pasien->update([
                'deskripsi_diri' => $request->deskripsi_diri,
            ]);

            DB::commit();
            $position = Pasien::orderBy('id')->pluck('id')->search($pasien->id) + 1;
            $perPage = 10;
            $page = ceil($position / $perPage);
            
            return redirect()->route('user-pasien.index', ['page' => $page])
                            ->with('success', 'Data pasien berhasil diubah!');

        } catch (\Exception $e) {
            DB::rollback();
            return redirect()->back()->with('error', 'Data pasien gagal diubah! Pesan error: ' . $e->getMessage());
        }
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(string $id)
    {
        $user = User::findOrFail($id);

        if ($user->foto_profil) {
            Storage::disk('public')->delete($user->foto_profil);
        }
        $userDeleted = $user->delete();

        if ($userDeleted) {
            return redirect()->back()->with('success', 'Data pasien berhasil dihapus!');
        } else {
            return redirect()->back()->with('error', 'Data pasien gagal dihapus!');
        }
    }
}
