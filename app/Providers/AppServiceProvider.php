<?php

namespace App\Providers;

use Illuminate\Support\Facades\Schema;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\View;
use Illuminate\Support\Facades\DB;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        $subscriptionPlan = null;

        if (Schema::hasTable('subscription_plan')) {
            $subscriptionPlan = DB::table('subscription_plan')->first();
        }
    
        // Bagikan data ke semua views
        View::share('subscriptionPlan', $subscriptionPlan);
    }
}
