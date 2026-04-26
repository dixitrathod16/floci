#!/usr/bin/env bats
# CloudFormation tests

setup() {
    load 'test_helper/common-setup'
    STACK_NAME="bats-cfn-stack-$(unique_name)"
    TEMPLATE_FILE=$(mktemp /tmp/cfn-bats-XXXXXX.yaml)
}

teardown() {
    aws_cmd cloudformation delete-stack --stack-name "$STACK_NAME" >/dev/null 2>&1 || true
    [ -n "$TEMPLATE_FILE" ] && rm -f "$TEMPLATE_FILE"
}

# ── CreateStack / DescribeStacks ──────────────────────────────────────────────

@test "CloudFormation: create stack reaches CREATE_COMPLETE" {
    cat > "$TEMPLATE_FILE" << 'EOF'
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: bats-cfn-basic-queue
EOF
    run aws_cmd cloudformation create-stack \
        --stack-name "$STACK_NAME" \
        --template-body "file://$TEMPLATE_FILE"
    assert_success

    run aws_cmd cloudformation describe-stacks --stack-name "$STACK_NAME"
    assert_success
    local stack_status
    stack_status=$(json_get "$output" '.Stacks[0].StackStatus')
    [ "$stack_status" = "CREATE_COMPLETE" ]
}

@test "CloudFormation: describe-stack-resources lists provisioned resources" {
    cat > "$TEMPLATE_FILE" << 'EOF'
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: bats-cfn-resources-queue
EOF
    aws_cmd cloudformation create-stack \
        --stack-name "$STACK_NAME" \
        --template-body "file://$TEMPLATE_FILE" >/dev/null

    run aws_cmd cloudformation describe-stack-resources --stack-name "$STACK_NAME"
    assert_success
    local count
    count=$(json_get "$output" '.StackResources | length')
    [ "$count" -gt 0 ]
}

@test "CloudFormation: delete stack removes resources" {
    cat > "$TEMPLATE_FILE" << 'EOF'
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: bats-cfn-delete-queue
EOF
    aws_cmd cloudformation create-stack \
        --stack-name "$STACK_NAME" \
        --template-body "file://$TEMPLATE_FILE" >/dev/null

    run aws_cmd cloudformation delete-stack --stack-name "$STACK_NAME"
    assert_success

    run aws_cmd cloudformation describe-stacks --stack-name "$STACK_NAME"
    # Stack should no longer exist
    [[ "$output" == *"does not exist"* ]]
    STACK_NAME=""  # prevent teardown from trying again
}

# ── aws cloudformation deploy (CreateChangeSet + ExecuteChangeSet by ARN) ─────
#
# Regression: DescribeChangeSet / ExecuteChangeSet failed when called with the
# changeset ARN (the AWS CLI always passes the ARN, not the short name).
# See: https://github.com/floci-io/floci/issues/606

@test "CloudFormation: deploy creates stack via changeset" {
    cat > "$TEMPLATE_FILE" << 'EOF'
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: bats-cfn-deploy-queue
EOF
    run aws_cmd cloudformation deploy \
        --stack-name "$STACK_NAME" \
        --template-file "$TEMPLATE_FILE"
    assert_success

    run aws_cmd cloudformation describe-stacks --stack-name "$STACK_NAME"
    assert_success
    local stack_status
    stack_status=$(json_get "$output" '.Stacks[0].StackStatus')
    [ "$stack_status" = "CREATE_COMPLETE" ]
}

@test "CloudFormation: deploy provisions resources correctly" {
    cat > "$TEMPLATE_FILE" << 'EOF'
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: bats-cfn-deploy-res-queue
EOF
    aws_cmd cloudformation deploy \
        --stack-name "$STACK_NAME" \
        --template-file "$TEMPLATE_FILE" >/dev/null

    run aws_cmd cloudformation describe-stack-resources --stack-name "$STACK_NAME"
    assert_success
    local resource_status
    resource_status=$(json_get "$output" '.StackResources[0].ResourceStatus')
    [ "$resource_status" = "CREATE_COMPLETE" ]
}
