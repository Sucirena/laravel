<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\SubscriptionPlan;
use App\Http\Requests\SubscriptionPlanRequest;
use Illuminate\Support\Facades\DB;

class SubscriptionPlanController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        // Ambil semua data subscription plan
        $plans = SubscriptionPlan::all();

        // Kirim data ke view
        return view('Admin/subscription', [
            'title' => 'Daftar Subscription Plan',
            'plans' => $plans,
        ]);
    }

    /**
     * Show the form for creating a new resource.
     */
    public function create()
    {
        //
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
    public function show(string $id)
    {
        //
    }

    /**
     * Show the form for editing the specified resource.
     */
    public function edit(string $id)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(SubscriptionPlanRequest $request, $id)
    {
        DB::beginTransaction();
    
        try {
            // Cari subscription plan berdasarkan ID, atau gagal jika tidak ditemukan
            $plan = SubscriptionPlan::findOrFail($id);
    
            // Update data utama subscription plan
            $plan->update([
                'name' => $request->name,
                'price' => $request->price,
                'duration' => $request->duration,
            ]);
    
            DB::commit();
            return redirect()->route('subscription.index')->with('success', 'Subscription plan berhasil diperbarui!');
        } catch (\Exception $e) {
            DB::rollBack();
            return back()->with('error', 'Subscription plan gagal diperbarui: ' . $e->getMessage());
        }
    }
    

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(string $id)
    {
        //
    }
}
