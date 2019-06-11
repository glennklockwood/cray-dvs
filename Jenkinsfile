#!/usr/bin/env groovy

pipeline {
  parameters {
    choice(name: 'VM_Node_Count', choices: '3\n1\n2\n4\n5\n6\n7\n8',
           description: 'Number of vm nodes to build. Default: 3')
    choice(name: 'Test_Class', choices: 'test\ntest-long',
           description: 'Class of tests to run. Default: test')
    booleanParam(name: 'Limit_DVS_Resources', defaultValue: false,
                 description: 'If checked, patch DVS source with patch files to limit DVS resources. Default: Unchecked')
    choice(name: 'OS_Distribution', choices: 'sles15sp0\nsles12sp3',
           description: 'What distribution to use for created VMs. default: sles15sp0')
    choice(name: 'OpenStack_VM_Flavor', choices:
           'highcpu.4\nstandard.1\nstandard.2\nstandard.4\nstandard.8\nstandard.16\nhighcpu.2\nhighcpu.8\nhighcpu.16\nhighmem.2\nhighmem.4\nhighmem.8',
           description: 'Openstack flavor to use for created VMs. Default: highcpu.4')
  }

  agent {
    // Note, this is only to ensure our agent has terraform present. The
    // Makefile in use here expects the binary "terraform" to exist.
    label { label "ci-dvs" }
  }

  triggers {
    // For now feature/shared/shasta is our "master" for our purposes.
    //
    // TODO: replace with master when this gets there.
    cron(env.BRANCH_NAME == 'feature/shared/shasta' ? 'H 6 * * *' : 'H 7 * * 1-5')
  }

  options {
    // Keep only 5 days worth of runs, and up to 5 days of runs.
    //
    // Should allow us to cleanup any failed runs manually with plenty of time
    // to spare.
    buildDiscarder(logRotator(numToKeepStr: '31', daysToKeepStr: '14'))
  }

  // Note, OS_PASSWORD and OS_USERNAME snagged through the credentials plugin
  environment {
    OS_AUTH_URL = 'https://craystack.us.cray.com:5000/v3'
    OS_IDENTITY_API_VERSION = '3'
    OS_INTERFACE = 'public'
    OS_PROJECT_ID = 'f92d6021a4bd432395163b75698d38c3'
    OS_PROJECT_NAME = 'ci-dvs'
    OS_REGION_NAME = 'RegionOne'
    OS_DOMAIN_NAME = 'Default'
    OS_USER_DOMAIN_NAME = 'Default'
  }

  stages {
    stage('setup') {
      steps {
        script {
          currentBuild.description = "Limit_DVS_Resources = ${Limit_DVS_Resources} Test_Class = ${Test_Class} Openstack_VM_Flavor = ${Openstack_VM_Flavor} VM_Node_Count = ${VM_Node_Count} OS_Distribution = ${OS_Distribution}"
          checkout scm
          // Generate a unique ssh key for terraform usage. TODO: maybe make
          // this a variable?
          sh "install -dm755 ${WORKSPACE}/.ssh/${BRANCH_NAME}"
          sh "ssh-keygen -t rsa -f ${WORKSPACE}/.ssh/${BRANCH_NAME}/ssh-key-${BUILD_NUMBER}"
          // Save our generated ssh keys in case we need to use them later on.
          dir("${WORKSPACE}/.ssh/${BRANCH_NAME}") {
            archiveArtifacts artifacts: "**/*${BUILD_NUMBER}*"
          }
        }
      }
    }
    stage('create vms') {
      steps {
        script {
          withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: 'ci-dvs-user-password'
                            , usernameVariable: 'OS_USERNAME', passwordVariable: 'OS_PASSWORD']]) {
            sh "make -C cray up SSH_KEY=${WORKSPACE}/.ssh/${BRANCH_NAME}/ssh-key-${BUILD_NUMBER} TF_VAR_os_flavor=${Openstack_VM_Flavor} TF_VAR_nodes=${VM_Node_Count} TF_VAR_distro=${OS_Distribution}"
            // Save the terraform state/directories as well in case cleanup
            // fails so we can more easily manually cleanup.
            dir("${WORKSPACE}/cray") {
              archiveArtifacts artifacts: "terraform.tfstate*"
            }
          }
        }
      }
    }
    stage('sync') {
      steps {
        script {
          withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: 'ci-dvs-user-password'
                            , usernameVariable: 'OS_USERNAME', passwordVariable: 'OS_PASSWORD']]) {
            sh "make -C cray -j rsync SSH_KEY=${WORKSPACE}/.ssh/${BRANCH_NAME}/ssh-key-${BUILD_NUMBER}"
          }
        }
      }
    }
    stage('patch') {
      steps {
        script {
          if (Limit_DVS_Resources == "true") {
            withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: 'ci-dvs-user-password'
                              , usernameVariable: 'OS_USERNAME', passwordVariable: 'OS_PASSWORD']]) {
              sh "make -C cray -j patch SSH_KEY=${WORKSPACE}/.ssh/${BRANCH_NAME}/ssh-key-${BUILD_NUMBER}"
            }
          } else {
            echo("Skipping patch phase")
          }
        }
      }
    }
    stage('build') {
      steps {
        script {
          withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: 'ci-dvs-user-password'
                            , usernameVariable: 'OS_USERNAME', passwordVariable: 'OS_PASSWORD']]) {
            sh "make -C cray -j dvs V=1 SSH_KEY=${WORKSPACE}/.ssh/${BRANCH_NAME}/ssh-key-${BUILD_NUMBER}"
          }
        }
      }
    }
    stage('install') {
      steps {
        script {
          withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: 'ci-dvs-user-password'
                            , usernameVariable: 'OS_USERNAME', passwordVariable: 'OS_PASSWORD']]) {
            sh "make -C cray -j install SSH_KEY=${WORKSPACE}/.ssh/${BRANCH_NAME}/ssh-key-${BUILD_NUMBER}"
          }
        }
      }
    }
    stage('load') {
      steps {
        script {
          withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: 'ci-dvs-user-password'
                            , usernameVariable: 'OS_USERNAME', passwordVariable: 'OS_PASSWORD']]) {
            sh "make -C cray -j load SSH_KEY=${WORKSPACE}/.ssh/${BRANCH_NAME}/ssh-key-${BUILD_NUMBER}"
          }
        }
      }
    }
    stage('test') {
      steps {
        script {
          withCredentials([[$class: 'UsernamePasswordMultiBinding'
                            , credentialsId: 'ci-dvs-user-password'
                            , usernameVariable: 'OS_USERNAME'
                            , passwordVariable: 'OS_PASSWORD']]) {
            // For things that are fast, 10 minutes should be more than enough (tm)(c)(r)
            def timeout_time = 10
            def timeout_unit = 'MINUTES'

            // Expensive tests take a LONG time to complete.
            // For now we'll allocate 2 hours to a long run.
            //
            // TODO: We should put a lock for long runs to make only one long
            // run at a time possible.
            if (!["test", "test-fast"].contains(Test_Class)) {
              timeout_time = 2
              timeout_unit = 'HOURS'
            }
            timeout(time: timeout_time, unit: timeout_unit) {
              sh "make -C cray ${Test_Class} SSH_KEY=${WORKSPACE}/.ssh/${BRANCH_NAME}/ssh-key-${BUILD_NUMBER}"
            }
          }
        }
      }
    }
  }

  post {
    failure {
      script {
        if (env.BRANCH_NAME == 'feature/shared/shasta') {
          emailext (
            subject: "ci-dvs Failure: job ${env.JOB_NAME} #${env.BUILD_NUMBER}",
            body: """ci-dvs run: job ${env.JOB_NAME} build # ${env.BUILD_NUMBER}:

Check console output at ${env.BUILD_URL} for more details

Do not reply to this email address, this is an automated message!""",
            recipientProviders: [[$class: 'DevelopersRecipientProvider']],
            to: 'ci-dvs-notifications@cray.com'
            )
        }
      }
    }
    always {
      // If make test fails as an example, we don't get the results.tar.gz file
      //
      // This post action just scps that file if it exists so we can use it to
      // parse tap results.
      script {
        withCredentials([[$class: 'UsernamePasswordMultiBinding'
                          , credentialsId: 'ci-dvs-user-password'
                          , usernameVariable: 'OS_USERNAME'
                          , passwordVariable: 'OS_PASSWORD']]) {
          sh "make -C cray results SSH_KEY=${WORKSPACE}/.ssh/${BRANCH_NAME}/ssh-key-${BUILD_NUMBER}"
        }

        def fstest_dir = "${WORKSPACE}/cray/mnt-results/test_fstest.sh"

        if (fileExists("${fstest_dir}/results.tar.gz")) {
          dir(fstest_dir) {
            sh "tar xzvf ${fstest_dir}/results.tar.gz"
            archiveArtifacts artifacts: "results.tar.gz"
          }
          def fstest_tap_dir = "${fstest_dir}/mnt/dvs/source/fstest.git"
          if (fileExists(fstest_tap_dir)) {
            dir(fstest_tap_dir){
              step([$class: 'TapPublisher'
               , discardOldReports: false
               , enableSubtests: false
               , failIfNoResults: true
               , failedTestsMarkBuildAsFailure: true
               , flattenTapResult: false
               , includeCommentDiagnostics: true
               , outputTapToConsole: true
               , planRequired: true
               , showOnlyFailures: false
               , skipIfBuildNotOk: false
               , stripSingleParents: false
               , testResults: '**/*.t'
               , todoIsFailure: false
               , validateNumberOfTests: false
               , verbose: true])
            }
          } else {
            echo("No extracted test results found")
          }
        } else {
          echo("No fstest test results file found")
        }
        dir("${WORKSPACE}/cray") {
          if (fileExists("${WORKSPACE}/cray/tap-results")) {
            archiveArtifacts artifacts: "tap-results/**/*"
          }
          if (fileExists("${WORKSPACE}/cray/mnt-results")) {
            archiveArtifacts artifacts: "mnt-results/**/*"
          }
        }
      }
    }
    cleanup {
      withCredentials([[$class: 'UsernamePasswordMultiBinding'
                        , credentialsId: 'ci-dvs-user-password'
                        , usernameVariable: 'OS_USERNAME'
                        , passwordVariable: 'OS_PASSWORD']]) {
        // Note, cleanup *can* fail or temporarily not work. We shouldn't assume
        // that clean will work every time.
        //
        // Example:
        // random_string.uniq: Refreshing state... (ID: XxpwX1O7)
        // openstack_compute_secgroup_v2.network_sg: Refreshing state... (ID: 13246c40-70ed-4ea9-ae8c-8d514e7a38b6)
        // openstack_compute_keypair_v2.terraform: Refreshing state... (ID: dvs-ssh-key-XxpwX1O7)
        // openstack_networking_router_v2.router: Refreshing state... (ID: 8384655a-a396-4330-8394-9b72096f831e)
        //
        // Error: Error refreshing state: 1 error(s) occurred:
        //
        // * openstack_compute_secgroup_v2.network_sg: 1 error(s) occurred:
        //
        // * openstack_compute_secgroup_v2.network_sg: openstack_compute_secgroup_v2.network_sg: security group: The service is currently unable to handle the request due to a temporary overloading or maintenance. This is a temporary condition. Try again later.
        //
        // As such, retry 5 times, with an interval of 5 seconds between
        // retries, if we can't destroy things after that length of time, a
        // human will have to clean things up manually.
        retry(5) {
          sh "make -C cray clean SSH_KEY=${WORKSPACE}/.ssh/${BRANCH_NAME}/ssh-key-${BUILD_NUMBER} || sleep 5"
        }
      }
    }
  }
}
